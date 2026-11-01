// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// ScopeTopology borne les lectures de topologie aux passerelles que l'appelant voit (rbac.NodeScope) : la liste des
// nœuds, un nœud, les événements et les groupes. Un Agent suit sa passerelle. Les vues qui ne se découpent pas par
// passerelle (direct, santé des backends, état du WAF) sont réservées à qui voit toute la topologie. Un administrateur,
// un accès à l'infrastructure sans critère et les écritures passent sans filtre.
func ScopeTopology(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := rbac.CallerFrom(r.Context())
			if caller == nil || caller.IsAdmin() || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
				next.ServeHTTP(w, r)
				return
			}
			ns := rbac.NodeScopeFor(r.Context(), caller)
			if ns.All() {
				next.ServeHTTP(w, r)
				return
			}
			path := r.URL.Path
			switch {
			case path == "/api/v1/nodes" || path == "/api/v1/nodes/":
				filterJSONList(w, r, next, func(row map[string]any) bool { return nodeRowVisible(ns, row) })
			case path == "/api/v1/node-events":
				filterJSONList(w, r, next, func(row map[string]any) bool { return ns.Edge(str(row["node_name"])) })
			case path == "/api/v1/architecture/groups":
				filterJSONMap(w, r, next, ns.GroupNamed)
			case strings.HasPrefix(path, "/api/v1/nodes/meta/"):
				next.ServeHTTP(w, r)
			case path == "/api/v1/nodes/live", path == "/api/v1/backends/health", path == "/api/v1/edges/waf-status":
				http.Error(w, "vue globale réservée aux accès à toute la topologie", http.StatusForbidden)
			case strings.HasPrefix(path, "/api/v1/nodes/"):
				id := strings.SplitN(strings.TrimPrefix(path, "/api/v1/nodes/"), "/", 2)[0]
				var name, role string
				if err := db.QueryRowContext(r.Context(), `SELECT node_name, role FROM nodes WHERE id=? OR node_name=?`, id, id).Scan(&name, &role); err != nil || role != "edge" || !ns.Edge(name) {
					http.Error(w, "nœud introuvable", http.StatusNotFound)
					return
				}
				next.ServeHTTP(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

func str(v any) string { s, _ := v.(string); return s }

// nodeRowVisible : une passerelle se juge par son groupe, un Agent par la passerelle qui le tient.
func nodeRowVisible(ns rbac.NodeScope, row map[string]any) bool {
	switch str(row["role"]) {
	case "edge":
		return ns.Edge(str(row["node_name"])) || ns.Edge(str(row["id"]))
	case "agent":
		return ns.Edge(str(row["target_edge"]))
	}
	return false
}

// capture exécute le handler et rend ce qu'il a répondu.
func capture(r *http.Request, next http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	return rec
}

func relay(w http.ResponseWriter, rec *httptest.ResponseRecorder, body []byte) {
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

func filterJSONList(w http.ResponseWriter, r *http.Request, next http.Handler, keep func(map[string]any) bool) {
	rec := capture(r, next)
	var rows []map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rows) != nil {
		relay(w, rec, rec.Body.Bytes())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if keep(row) {
			out = append(out, row)
		}
	}
	b, _ := json.Marshal(out)
	relay(w, rec, b)
}

func filterJSONMap(w http.ResponseWriter, r *http.Request, next http.Handler, keep func(string) bool) {
	rec := capture(r, next)
	var m map[string]json.RawMessage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &m) != nil {
		relay(w, rec, rec.Body.Bytes())
		return
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		if keep(k) {
			out[k] = v
		}
	}
	b, _ := json.Marshal(out)
	relay(w, rec, b)
}
