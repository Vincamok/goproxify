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

// ScopeSecurity borne la sécurité réseau aux passerelles et groupes que le périmètre de l'appelant désigne (ADR 0022) :
// les listes de bannissements, de menaces et de CVE sont filtrées par leur passerelle ou leur portée ; bannir,
// débannir et changer le statut d'une CVE se jugent sur la portée de l'objet. Une portée globale (sans passerelle) et
// les vues qui agrègent toute la plateforme n'appartiennent qu'à un accès sans critère. resolve est la table de
// permissions du service ; la surface applicative juge elle-même chaque proxy.
func ScopeSecurity(db *sql.DB, resolve rbac.GatePermission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := rbac.CallerFrom(r.Context())
			if caller == nil || caller.IsAdmin() {
				next.ServeHTTP(w, r)
				return
			}
			permission, _ := resolve(r)
			if strings.HasPrefix(permission, "surface:") || caller.Filter(permission).All() {
				next.ServeHTTP(w, r)
				return
			}
			ns := rbac.NodeScopeForPermission(r.Context(), caller, permission)
			parts := strings.FieldsFunc(strings.TrimPrefix(r.URL.Path, "/api/v1/security"), func(c rune) bool { return c == '/' })
			deny := func() { http.Error(w, "vue globale réservée aux accès sans périmètre", http.StatusForbidden) }
			switch {
			case len(parts) == 1 && parts[0] == "bans" && r.Method == http.MethodGet:
				filterJSONList(w, r, next, func(row map[string]any) bool {
					return scopeVisible(ns, str(row["target_scope"]), str(row["edge_name"]))
				})
			case len(parts) == 1 && parts[0] == "threats" && r.Method == http.MethodGet,
				len(parts) == 1 && parts[0] == "cves" && r.Method == http.MethodGet:
				filterJSONList(w, r, next, func(row map[string]any) bool { return scopeVisible(ns, "", str(row["edge_name"])) })
			case len(parts) == 1 && parts[0] == "bans" && r.Method == http.MethodPost:
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var ban struct {
					TargetScope string `json:"target_scope"`
				}
				_ = json.Unmarshal(body, &ban)
				if !scopeVisible(ns, ban.TargetScope, "") {
					http.Error(w, "hors de votre périmètre : un ban cible une passerelle ou un groupe que vous voyez", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			case len(parts) == 2 && parts[0] == "bans" && parts[1] != "history" && parts[1] != "countries" && parts[1] != "export" &&
				parts[1] != "preview" && parts[1] != "whitelist" && parts[1] != "import" && (r.Method == http.MethodDelete || r.Method == http.MethodPatch):
				if !banRowVisible(r, db, ns, parts[1]) {
					http.Error(w, "hors de votre périmètre", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			case len(parts) == 2 && parts[0] == "cves" && r.Method == http.MethodPatch:
				var edge string
				if err := db.QueryRowContext(r.Context(), `SELECT edge_name FROM security_cves WHERE id=?`, parts[1]).Scan(&edge); err == nil && !scopeVisible(ns, "", edge) {
					http.Error(w, "hors de votre périmètre", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			case len(parts) >= 1 && (parts[0] == "waf-config" || parts[0] == "threat-config") && strings.HasPrefix(permission, "engines:"):
				// Réglages d'un moteur : par passerelle ou groupe (?edge=) ; sans ?edge= c'est la configuration globale, aux
				// accès sans critère. Passer un signal en block exige en plus la case engines:enforce.
				edge := strings.TrimSpace(r.URL.Query().Get("edge"))
				if edge == "" || !(scopeVisible(ns, edge, "") || ns.GroupNamed(edge)) {
					http.Error(w, "passerelle visible requise (?edge=) : la configuration globale est réservée aux accès sans périmètre", http.StatusForbidden)
					return
				}
				if r.Method == http.MethodPut {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					if enginePutBlocks(body) && caller.Filter("engines:enforce").None() {
						http.Error(w, "passer un signal en block exige la case engines:enforce", http.StatusForbidden)
						return
					}
				}
				next.ServeHTTP(w, r)
			case len(parts) == 1 && parts[0] == "threat-references" && r.Method == http.MethodGet:
				next.ServeHTTP(w, r)
			default:
				deny()
			}
		})
	}
}

// scopeVisible juge la portée d'un objet de sécurité : « group:<nom> », le nom d'une passerelle, ou à défaut sa
// passerelle d'origine. Sans portée ni passerelle, l'objet est global : réservé aux accès sans critère.
func scopeVisible(ns rbac.NodeScope, scope, edge string) bool {
	if scope == "" {
		scope = edge
	}
	if name, ok := strings.CutPrefix(scope, "group:"); ok {
		return ns.GroupNamed(name)
	}
	return scope != "" && ns.Edge(scope)
}

func banRowVisible(r *http.Request, db *sql.DB, ns rbac.NodeScope, id string) bool {
	var scope, edge string
	if err := db.QueryRowContext(r.Context(), `SELECT target_scope, edge_name FROM security_bans WHERE id=?`, id).Scan(&scope, &edge); err != nil {
		return true // introuvable : le handler répond 404, rien à protéger
	}
	return scopeVisible(ns, scope, edge)
}

// enginePutBlocks dit si une configuration de moteur envoyée en PUT peut faire bloquer des clients : une valeur « block »
// n'importe où, ou aucun « mode » à la racine (le défaut d'Ephor est block). Le critère est volontairement large : un
// compte sans la case engines:enforce ne règle que des moteurs en detect.
func enginePutBlocks(body []byte) bool {
	var cfg map[string]any
	if json.Unmarshal(body, &cfg) != nil {
		return true
	}
	if _, hasMode := cfg["mode"]; !hasMode {
		return true
	}
	return containsBlock(cfg)
}

func containsBlock(v any) bool {
	switch x := v.(type) {
	case string:
		return x == "block"
	case []any:
		for _, e := range x {
			if containsBlock(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if containsBlock(e) {
				return true
			}
		}
	}
	return false
}
