// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package siem exporte les logs d'une passerelle vers un SIEM (ADR 0012). L'exporteur lit la base de logs locale avec
// son propre curseur persistant : il ne dépend pas de l'Admin, et un SIEM en panne ne perd rien tant que la base garde
// les lignes. La livraison est « au moins une fois » ; chaque ligne porte un identifiant stable pour dédoublonner.
package siem

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Types de destination.
const (
	// TypeSyslog : RFC 5424 sur TCP (RFC 6587, comptage d'octets), avec TLS si TLS est vrai.
	TypeSyslog = "syslog"
	// TypeHTTP : un lot de lignes JSON (NDJSON) par requête POST.
	TypeHTTP = "http"
	// TypeOTLP : OTLP/HTTP, encodage JSON (ExportLogsServiceRequest) ; l'adresse est l'URL complète du collecteur,
	// par exemple http://collector.example.com:4318/v1/logs.
	TypeOTLP = "otlp"
)

// Origine d'un nouveau flux : ce qu'une destination reçoit la première fois.
const (
	FromNow = "now" // seulement ce qui arrive après la création (défaut)
)

// Limites : une configuration illisible ou démesurée ne doit pas faire tomber la passerelle.
const (
	MaxDestinations = 8
	MaxBackfillHrs  = 24 * 365
	MaxHeaders      = 16
	MaxNodes        = 64
)

// Config est la configuration de l'exporteur, poussée par l'Admin et gardée chiffrée sur la passerelle.
type Config struct {
	Enabled      bool          `json:"enabled"`
	Destinations []Destination `json:"destinations"`
}

// Destination est un SIEM à alimenter.
type Destination struct {
	// ID : identifiant stable, clé du curseur. Vide à la création : l'Admin en attribue un.
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Address : « hôte:port » pour syslog ; URL http(s) pour HTTP et OTLP.
	Address string `json:"address"`
	// TLS (syslog) : chiffre la connexion. CAPEM : autorité à faire confiance en plus de celles du système.
	TLS   bool   `json:"tls,omitempty"`
	CAPEM string `json:"ca_pem,omitempty"`
	// Headers (HTTP, OTLP) : en-têtes ajoutés à chaque requête, par exemple un jeton. Ce sont des secrets.
	Headers map[string]string `json:"headers,omitempty"`
	// Kinds : types à exporter, « access » et/ou « system » ; vide, les deux.
	Kinds []string `json:"kinds,omitempty"`
	// MinLevel : niveau minimal, « info » (défaut), « warn » ou « error ».
	MinLevel string `json:"min_level,omitempty"`
	// SecurityOnly : seulement les accès signalés par le WAF ou Ephor (les logs système ne sont pas filtrés par là).
	SecurityOnly bool `json:"security_only,omitempty"`
	// BackfillHours : à la création, repart de N heures en arrière au lieu de « maintenant » (0 : maintenant).
	BackfillHours int `json:"backfill_hours,omitempty"`
	// AlertAfterMinutes : retard au-delà duquel l'Admin alerte (défaut 60).
	AlertAfterMinutes int `json:"alert_after_minutes,omitempty"`
	// Facility (syslog) : 0 à 23, défaut 16 (local0).
	Facility *int `json:"facility,omitempty"`
	// Nodes : noms des passerelles qui exportent vers cette destination ; vide, toutes. L'Admin filtre à la poussée et
	// n'envoie pas ce champ : une passerelle ne reçoit que ses destinations.
	Nodes []string `json:"nodes,omitempty"`
}

var levels = map[string]int{"debug": 0, "info": 1, "warn": 2, "warning": 2, "error": 3}

// LevelRank classe un niveau de log ; un niveau inconnu vaut « info ».
func LevelRank(level string) int {
	if r, ok := levels[strings.ToLower(level)]; ok {
		return r
	}
	return levels["info"]
}

// Wants dit si la destination exporte ce type de logs.
func (d Destination) Wants(kind string) bool {
	if len(d.Kinds) == 0 {
		return true
	}
	for _, k := range d.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// AlertAfter rend le retard d'alerte en minutes.
func (d Destination) AlertAfter() int {
	if d.AlertAfterMinutes <= 0 {
		return 60
	}
	return d.AlertAfterMinutes
}

// Validate refuse une configuration inutilisable. Une configuration désactivée est valide même vide.
func (c Config) Validate() error {
	if len(c.Destinations) > MaxDestinations {
		return fmt.Errorf("au plus %d destinations", MaxDestinations)
	}
	seen := map[string]bool{}
	for i, d := range c.Destinations {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("destination %d (%s) : %w", i+1, d.Name, err)
		}
		if d.ID == "" {
			return fmt.Errorf("destination %d (%s) : identifiant manquant", i+1, d.Name)
		}
		if seen[d.ID] {
			return fmt.Errorf("destination %d (%s) : identifiant en double", i+1, d.Name)
		}
		seen[d.ID] = true
	}
	return nil
}

// Validate vérifie une destination.
func (d Destination) Validate() error {
	if strings.TrimSpace(d.Name) == "" || len(d.Name) > 80 {
		return errors.New("nom requis (80 caractères au plus)")
	}
	switch d.Type {
	case TypeSyslog:
		host, port, err := net.SplitHostPort(d.Address)
		if err != nil || host == "" || port == "" {
			return errors.New("adresse syslog attendue sous la forme hôte:port")
		}
	case TypeHTTP, TypeOTLP:
		u, err := url.Parse(d.Address)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("URL http ou https attendue")
		}
		if len(d.Headers) > MaxHeaders {
			return fmt.Errorf("au plus %d en-têtes", MaxHeaders)
		}
		for k, v := range d.Headers {
			if k == "" || strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
				return errors.New("en-tête invalide")
			}
		}
	default:
		return fmt.Errorf("type inconnu %q (syslog, http ou otlp)", d.Type)
	}
	for _, k := range d.Kinds {
		if k != "access" && k != "system" {
			return fmt.Errorf("type de logs inconnu %q (access ou system)", k)
		}
	}
	if d.MinLevel != "" {
		if _, ok := levels[strings.ToLower(d.MinLevel)]; !ok {
			return fmt.Errorf("niveau inconnu %q (info, warn ou error)", d.MinLevel)
		}
	}
	if d.BackfillHours < 0 || d.BackfillHours > MaxBackfillHrs {
		return errors.New("backfill_hours hors limites")
	}
	if d.AlertAfterMinutes < 0 {
		return errors.New("alert_after_minutes négatif")
	}
	if len(d.Nodes) > MaxNodes {
		return fmt.Errorf("au plus %d passerelles", MaxNodes)
	}
	for _, n := range d.Nodes {
		if strings.TrimSpace(n) == "" || len(n) > 128 {
			return errors.New("nom de passerelle invalide")
		}
	}
	if d.Facility != nil && (*d.Facility < 0 || *d.Facility > 23) {
		return errors.New("facility entre 0 et 23")
	}
	if d.TLS && d.Type != TypeSyslog {
		return errors.New("tls ne s'applique qu'à syslog (utiliser https pour HTTP)")
	}
	return nil
}
