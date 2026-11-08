// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// portalScopeTables dit, pour chaque sous-service du portail qui stocke ses objets, la table et la colonne qui portent leur
// portée (une passerelle, ou « group:<nom> »).
var portalScopeTables = map[string][2]string{
	"users":              {"portal_users", "home_edge"},
	"groups":             {"portal_groups", "edge_name"},
	"destinations":       {"portal_destinations", "edge_name"},
	"destination-groups": {"portal_dest_groups", "edge_name"},
	"dest-sources":       {"portal_dest_sources", "edge_name"},
	"dest-candidates":    {"portal_dest_candidates", "edge_name"},
	"access-requests":    {"portal_access_requests", "edge_name"},
}

// portalBodyScopeFields sont les champs d'un corps de requête qui placent un objet dans une portée.
var portalBodyScopeFields = []string{"home_edge", "edge_name", "edge"}

// ScopePortal borne le portail Access aux passerelles et groupes que le périmètre de l'appelant désigne (ADR 0022).
// Les handlers du portail désignent la passerelle par ?edge= et chargent les objets par identifiant : la garde exige donc
//
//   - une passerelle visible pour toute liste, création et réglage (?edge= obligatoire) ;
//   - que la portée de chaque objet visé par son identifiant (colonne home_edge ou edge_name) soit visible ;
//   - que la portée portée par le corps (home_edge, edge_name, edge) soit visible : on ne déplace pas un objet hors de
//     son périmètre.
//
// Les modèles de pages sont globaux : réservés aux accès sans critère. Un accès sans critère et un administrateur passent.
func ScopePortal(db *sql.DB, resolve rbac.GatePermission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := rbac.CallerFrom(r.Context())
			if caller == nil || caller.IsAdmin() {
				next.ServeHTTP(w, r)
				return
			}
			permission, _ := resolve(r)
			if caller.Filter(permission).All() {
				next.ServeHTTP(w, r)
				return
			}
			ns := rbac.NodeScopeForPermission(r.Context(), caller, permission)
			deny := func(msg string) { http.Error(w, msg, http.StatusForbidden) }
			visible := func(scope string) bool {
				scope = strings.TrimSpace(scope)
				return scope != "" && (scopeVisible(ns, scope, "") || ns.GroupNamed(scope))
			}

			if strings.HasPrefix(r.URL.Path, "/api/v1/portal-page-templates") {
				deny("modèles de pages globaux : réservés aux accès sans périmètre")
				return
			}
			parts := strings.FieldsFunc(strings.TrimPrefix(r.URL.Path, "/api/v1/portal"), func(c rune) bool { return c == '/' })
			edge := portalEdgeParam(r)
			if edge != "" && !visible(edge) {
				deny("hors de votre périmètre : passerelle ou groupe non visible")
				return
			}

			sub := ""
			if len(parts) > 0 {
				sub = parts[0]
			}
			// Un objet désigné par son identifiant : sa portée en base doit être visible.
			if table, ok := portalScopeTables[sub]; ok && len(parts) >= 2 {
				var scope string
				if err := db.QueryRowContext(r.Context(), `SELECT `+table[1]+` FROM `+table[0]+` WHERE id=?`, parts[1]).Scan(&scope); err == nil && !visible(scope) {
					deny("hors de votre périmètre")
					return
				}
			} else if edge == "" {
				// Liste, création, réglage, recordings, sessions, politique, audit… : la passerelle est obligatoire.
				deny("passerelle requise (?edge=) : un accès à périmètre ne lit pas tout le portail")
				return
			}

			// La portée portée par le corps ne sort pas du périmètre.
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Body != nil {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var fields map[string]json.RawMessage
				if json.Unmarshal(body, &fields) == nil {
					for _, key := range portalBodyScopeFields {
						raw, present := fields[key]
						if !present {
							continue
						}
						var value string
						if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" && !visible(value) {
							deny("hors de votre périmètre : la portée de l'objet n'est pas visible")
							return
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
