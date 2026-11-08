// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package destsync range les sources de destinations du portail Access (ADR 0024) : des modules du registre
// commun (internal/modules, ADR 0007) qui interrogent l'API d'une plateforme (Proxmox, cloud, inventaire…) et
// listent les machines joignables en SSH. Une source ne modifie rien chez le fournisseur ; l'exécuteur
// (Runner) la rejoue à intervalle régulier et remet l'inventaire à l'Admin, qui décide de ce qui est publié.
//
// Autonomie (ADR 0006) : une source ne dépend que de sa configuration, poussée avec celle du portail et gardée
// dans sa copie locale chiffrée. Elle tourne sans l'Admin.
package destsync

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/modules"
)

// Machine est une machine joignable en SSH découverte chez un fournisseur.
type Machine struct {
	// ExternalID identifie la machine chez le fournisseur, de façon stable (vmid, UUID, identifiant d'instance) :
	// c'est la clé de rapprochement avec la destination publiée.
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	// Host est l'adresse joignable depuis la passerelle ; vide quand le fournisseur n'en connaît pas.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// Tags sont les étiquettes du fournisseur (pool, tags Proxmox, labels), déjà normalisées.
	Tags    []string `json:"tags,omitempty"`
	Running bool     `json:"running"`
	// Detail est affiché tel quel (nœud, type, région…) ; il ne sert à aucune décision.
	Detail map[string]string `json:"detail,omitempty"`
}

// Source liste les machines d'un fournisseur.
type Source interface {
	List(ctx context.Context) ([]Machine, error)
}

// Factory construit une source depuis sa configuration saisie. Elle contrôle les valeurs que le manifeste ne
// peut pas contrôler (URL bien formée) et renvoie une erreur sinon.
type Factory func(cfg map[string]any) (Source, error)

// Registry range les types de sources.
type Registry = modules.Registry[Factory]

// NewRegistry crée un registre vide (les tests y enregistrent leurs propres sources).
func NewRegistry() *Registry { return modules.NewRegistry[Factory]() }

var builtin = NewRegistry()

// Register déclare un type de source. À appeler depuis init().
func Register(m modules.Manifest, f Factory) { builtin.Register(m, f) }

// Manifests retourne les manifestes des types de sources, dans l'ordre de déclaration.
func Manifests() []modules.Manifest { return builtin.Manifests() }

// ManifestOf retourne le manifeste d'un type.
func ManifestOf(typ string) (modules.Manifest, bool) {
	_, m, ok := builtin.Lookup(typ)
	return m, ok
}

// Build construit la source d'un type du registre commun.
func Build(typ string, cfg map[string]any) (Source, error) { return buildFrom(builtin, typ, cfg) }

func buildFrom(reg *Registry, typ string, cfg map[string]any) (Source, error) {
	f, _, ok := reg.Lookup(typ)
	if !ok {
		return nil, fmt.Errorf("type de source inconnu : %s", typ)
	}
	return f(cfg)
}

// SourceConfig est une source configurée, telle que l'Admin la pousse à la passerelle (secrets en clair : le
// canal est celui de toute la configuration du portail, et la copie locale est chiffrée).
type SourceConfig struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name,omitempty"`
	Enabled   bool           `json:"enabled"`
	IntervalS int            `json:"interval_s,omitempty"`
	Config    map[string]any `json:"config"`
}

// Bornes de l'intervalle de synchronisation.
const (
	DefaultInterval = 300
	MinInterval     = 60
)

// Interval retourne l'intervalle effectif, en secondes.
func (c SourceConfig) Interval() int {
	switch {
	case c.IntervalS <= 0:
		return DefaultInterval
	case c.IntervalS < MinInterval:
		return MinInterval
	}
	return c.IntervalS
}

// --- aides communes aux fournisseurs ---------------------------------------------------------------------------------

func str(cfg map[string]any, key string) string {
	switch v := cfg[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func boolean(cfg map[string]any, key string, def bool) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "oui":
			return true
		case "false", "0", "no", "non":
			return false
		}
	}
	return def
}

func integer(cfg map[string]any, key string, def int) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil {
			return n
		}
	}
	return def
}

// normalizeTags met les étiquettes en minuscules, sans doublon ni vide, triées.
func normalizeTags(in ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// pickIPv4 choisit l'adresse à publier parmi celles d'une machine : la première IPv4 privée, sinon la première IPv4
// publique ; jamais une adresse de bouclage ou de lien local. Vide : aucune. Les interfaces virtuelles (ponts Docker,
// veth) sont écartées en amont, par leur nom.
func pickIPv4(addrs []string) string {
	var public string
	for _, a := range addrs {
		if i := strings.IndexByte(a, '/'); i >= 0 {
			a = a[:i]
		}
		ip := net.ParseIP(strings.TrimSpace(a))
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if ip.IsPrivate() {
			return ip.String()
		}
		if public == "" {
			public = ip.String()
		}
	}
	return public
}
