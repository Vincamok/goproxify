// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type TopologySnapshotsHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type topologySnapshot struct {
	ID        string          `json:"id"`
	Label     string          `json:"label"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt time.Time       `json:"created_at"`
}

func (h *TopologySnapshotsHandler) ensureTable() {
	h.DB.Exec(`CREATE TABLE IF NOT EXISTS topology_snapshots (
		id         TEXT PRIMARY KEY,
		label      TEXT NOT NULL DEFAULT '',
		snapshot   TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
}

func (h *TopologySnapshotsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/topology-snapshots")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPost && id != "" && action == "restore":
		h.restore(w, r, id)
	case r.Method == http.MethodDelete && id != "" && action == "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *TopologySnapshotsHandler) list(w http.ResponseWriter, r *http.Request) {
	h.ensureTable()
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, label, snapshot, created_at FROM topology_snapshots ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]topologySnapshot, 0)
	for rows.Next() {
		var s topologySnapshot
		var raw string
		if err := rows.Scan(&s.ID, &s.Label, &raw, &s.CreatedAt); err != nil {
			continue
		}
		s.Snapshot = json.RawMessage(raw)
		result = append(result, s)
	}
	jsonOK(w, result)
}

func (h *TopologySnapshotsHandler) create(w http.ResponseWriter, r *http.Request) {
	h.ensureTable()
	var req struct {
		Label string `json:"label"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	snap, err := h.captureSnapshot(r)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	var s topologySnapshot
	err = h.DB.QueryRowContext(r.Context(),
		`INSERT INTO topology_snapshots(id, label, snapshot)
		 VALUES('tsnap_'||lower(hex(randomblob(6))),?,?) RETURNING id, label, snapshot, created_at`,
		req.Label, string(snap),
	).Scan(&s.ID, &s.Label, new(string), &s.CreatedAt)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("topology_snapshots: insert", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	s.Snapshot = snap
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, s)
}

func (h *TopologySnapshotsHandler) restore(w http.ResponseWriter, r *http.Request, id string) {
	h.ensureTable()
	var raw string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT snapshot FROM topology_snapshots WHERE id=?`, id,
	).Scan(&raw)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	var snap struct {
		DeclaredNodes []json.RawMessage `json:"declared_nodes"`
	}
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM declared_nodes`); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	for _, dnRaw := range snap.DeclaredNodes {
		var dn struct {
			Role        string `json:"role"`
			Name        string `json:"name"`
			Region      string `json:"region"`
			Environment string `json:"environment"`
			Config      string `json:"config"`
		}
		if err := json.Unmarshal(dnRaw, &dn); err != nil {
			continue
		}
		cfg := dn.Config
		if cfg == "" {
			cfg = "{}"
		}
		tx.ExecContext(r.Context(), //nolint:errcheck
			`INSERT INTO declared_nodes(id, role, name, region, environment, config)
			 VALUES('dn_'||lower(hex(randomblob(6))),?,?,?,?,?)`,
			dn.Role, dn.Name, dn.Region, dn.Environment, cfg,
		)
	}

	if err := tx.Commit(); err != nil {
		if !isCtxErr(err) {
			h.Log.Error("topology_snapshots: restore commit", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	h.Log.Info("topology_snapshots: restored", "id", id, "declared_nodes", len(snap.DeclaredNodes))
	jsonOK(w, map[string]any{"restored": true, "declared_nodes": len(snap.DeclaredNodes)})
}

func (h *TopologySnapshotsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.ensureTable()
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM topology_snapshots WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// captureSnapshot prend un instantané de declared_nodes.
func (h *TopologySnapshotsHandler) captureSnapshot(r *http.Request) (json.RawMessage, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, role, name, region, environment, config, created_at FROM declared_nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]map[string]any, 0)
	for rows.Next() {
		var id, role, name, region, env, cfg string
		var createdAt time.Time
		if err := rows.Scan(&id, &role, &name, &region, &env, &cfg, &createdAt); err != nil {
			continue
		}
		nodes = append(nodes, map[string]any{
			"id":          id,
			"role":        role,
			"name":        name,
			"region":      region,
			"environment": env,
			"config":      cfg,
			"created_at":  createdAt.Format(time.RFC3339),
		})
	}

	return json.Marshal(map[string]any{
		"declared_nodes": nodes,
		"captured_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// AutoSnapshot crée un snapshot automatique étiqueté, en ignorant les erreurs.
func (h *TopologySnapshotsHandler) AutoSnapshot(label string) {
	if h == nil || h.DB == nil {
		return
	}
	h.ensureTable()
	snap, err := h.captureSnapshot(&http.Request{})
	if err != nil {
		return
	}
	h.DB.Exec( //nolint:errcheck
		`INSERT INTO topology_snapshots(id, label, snapshot)
		 VALUES('tsnap_'||lower(hex(randomblob(6))),?,?)`,
		label, string(snap),
	)
	// Keep at most 100 snapshots
	h.DB.Exec(`DELETE FROM topology_snapshots WHERE id NOT IN (SELECT id FROM topology_snapshots ORDER BY created_at DESC LIMIT 100)`) //nolint:errcheck
}
