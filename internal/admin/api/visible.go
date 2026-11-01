// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Les handlers de lecture filtrent ce qu'ils renvoient d'après les accès de l'appelant (ADR 0022). La garde
// (rbac.Gate) a rangé l'appelant dans le contexte ; sans garde (appel direct, test), rien n'est restreint.

// visibility rend ce que l'appelant voit pour la permission ; ok est faux quand il n'a pas de garde à appliquer.
func visibility(r *http.Request, permission string) (v rbac.Visibility, restricted bool) {
	c := rbac.CallerFrom(r.Context())
	if c == nil || c.IsAdmin() {
		return rbac.Visibility{}, false
	}
	return rbac.VisibilityFor(r.Context(), c, permission), true
}

// visibleCerts rend le test de visibilité d'un certificat par son nom.
func visibleCerts(r *http.Request) func(name string) bool {
	v, restricted := visibility(r, "certs:read")
	if !restricted {
		return func(string) bool { return true }
	}
	return v.CertName
}

// visibleAlertEvents ne garde que les événements dont le domaine est visible ; un événement sans domaine (état d'une
// passerelle, du moteur…) n'est visible que d'un accès sans critère.
func visibleAlertEvents(r *http.Request, events []map[string]any) []map[string]any {
	v, restricted := visibility(r, "alerts:read")
	if !restricted || v.All() {
		return events
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		detail, _ := e["detail"].(map[string]any)
		for _, key := range []string{"domain", "host"} {
			if domain, _ := detail[key].(string); domain != "" && v.Host(domain) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// visibleAlertRule rend le test de visibilité d'une règle d'après son périmètre : une règle limitée à un domaine que
// l'appelant voit ; une règle sans domaine (toutes les passerelles) n'est visible que d'un accès sans critère.
func visibleAlertRule(r *http.Request) func(scope any) bool {
	v, restricted := visibility(r, "alerts:read")
	if !restricted || v.All() {
		return func(any) bool { return true }
	}
	return func(scope any) bool {
		m, _ := scope.(map[string]any)
		glob, _ := m["domain_glob"].(string)
		return v.Pattern(glob)
	}
}

// requireUnrestricted refuse (403) à un accès à périmètre une lecture qui agrège toute la plateforme (totaux, analyses
// de trafic) et ne se découpe pas par hôte : elle est réservée aux administrateurs et aux accès sans critère.
func requireUnrestricted(w http.ResponseWriter, r *http.Request, permission string) bool {
	v, restricted := visibility(r, permission)
	if restricted && !v.All() {
		http.Error(w, "vue globale réservée aux accès sans périmètre", http.StatusForbidden)
		return false
	}
	return true
}
