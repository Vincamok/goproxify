// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package channels implémente les adaptateurs de notification pour chaque canal.
// Il ne doit pas importer le package parent alerting pour éviter les cycles.
//
// Chaque type de canal est un module du registre commun (internal/modules) : il déclare un
// manifeste (champs, secrets, champs requis) et une fabrique. Ajouter un canal = un fichier qui
// appelle Register depuis init() ; l'API, le masquage des secrets et le formulaire de l'interface
// en découlent.
package channels

import (
	"context"
	"fmt"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// Message est le payload envoyé à un canal de notification.
// Les champs Trigger et Severity sont des chaînes brutes pour éviter le cycle d'import.
type Message struct {
	RuleName string
	Trigger  string
	Severity string
	Title    string
	Body     string
	Detail   map[string]any
	FiredAt  time.Time
}

// Channel décrit un canal de notification stocké en DB.
type Channel struct {
	ID      string
	Name    string
	Type    string
	Config  map[string]any
	Enabled bool
}

// Sender envoie un message via un canal spécifique.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Factory construit un Sender depuis la configuration stockée. Elle est tolérante : une
// configuration partielle (canal créé avant l'introduction de la validation) donne un Sender dont
// l'envoi échoue proprement, jamais une erreur de construction.
type Factory func(cfg map[string]any) Sender

var registry = modules.NewRegistry[Factory]()

// Register déclare un type de canal. À appeler depuis init() ; panique sur un manifeste invalide
// ou un type en double.
func Register(m modules.Manifest, f Factory) { registry.Register(m, f) }

// Manifests retourne les manifestes de tous les types de canal, dans l'ordre de déclaration.
func Manifests() []modules.Manifest { return registry.Manifests() }

// ManifestOf retourne le manifeste d'un type de canal.
func ManifestOf(typ string) (modules.Manifest, bool) {
	_, m, ok := registry.Lookup(typ)
	return m, ok
}

// Types retourne les types de canal connus, triés.
func Types() []string { return registry.Types() }

// Build instancie le bon Sender selon le type de canal.
func Build(ch Channel) (Sender, error) {
	f, _, ok := registry.Lookup(ch.Type)
	if !ok {
		return nil, fmt.Errorf("type de canal inconnu : %q", ch.Type)
	}
	return f(ch.Config), nil
}

func str(cfg map[string]any, k string) string {
	if v, ok := cfg[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intv(cfg map[string]any, k string, def int) int {
	if v, ok := cfg[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func strSlice(cfg map[string]any, k string) []string {
	v, ok := cfg[k]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if sv, ok := s.(string); ok {
				out = append(out, sv)
			}
		}
		return out
	}
	return nil
}

// MaskConfig masque les secrets de la configuration d'un canal (export, sorties MCP).
func MaskConfig(typ string, cfg map[string]any) map[string]any {
	if m, ok := ManifestOf(typ); ok && cfg != nil {
		return m.Mask(cfg)
	}
	return cfg
}

// KeepConfigSecrets conserve les secrets enregistrés quand la nouvelle configuration les omet ou renvoie le masque.
func KeepConfigSecrets(typ string, old, next map[string]any) map[string]any {
	if m, ok := ManifestOf(typ); ok && old != nil && next != nil {
		return m.KeepSecrets(old, next)
	}
	return next
}
