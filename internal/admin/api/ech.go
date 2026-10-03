// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/ech"
)

// ECHPusher envoie le jeu de clés ECH aux passerelles.
type ECHPusher interface {
	PushECHKeys(ctx context.Context)
}

// ECHHandler gère /api/v1/ech : activation d'Encrypted Client Hello, rotation des clés et valeur
// à publier dans le DNS. Les clés privées ne sont jamais renvoyées.
type ECHHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher ECHPusher
}

func (h *ECHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/ech"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.get(w, r)
	case rest == "" && r.Method == http.MethodPut:
		h.put(w, r)
	case rest == "rotate" && r.Method == http.MethodPost:
		h.rotate(w, r)
	case strings.HasPrefix(rest, "keys/") && r.Method == http.MethodDelete:
		h.deleteKey(w, r, strings.TrimPrefix(rest, "keys/"))
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method_not_allowed")
	}
}

func (h *ECHHandler) get(w http.ResponseWriter, r *http.Request) {
	st, err := ech.NewStore(h.DB).Status()
	if err != nil {
		h.Log.Error("ech: lecture", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, st)
}

func (h *ECHHandler) put(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled    bool   `json:"enabled"`
		PublicName string `json:"public_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	req.PublicName = strings.ToLower(strings.TrimSpace(req.PublicName))
	if err := ech.NewStore(h.DB).Configure(req.Enabled, req.PublicName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.push()
	h.get(w, r)
}

func (h *ECHHandler) rotate(w http.ResponseWriter, r *http.Request) {
	st := ech.NewStore(h.DB)
	enabled, publicName := st.Settings()
	if !enabled {
		http.Error(w, "ECH n'est pas activé", http.StatusConflict)
		return
	}
	if _, err := st.Rotate(publicName); err != nil {
		h.Log.Error("ech: rotation", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	h.push()
	h.get(w, r)
}

func (h *ECHHandler) deleteKey(w http.ResponseWriter, r *http.Request, id string) {
	if err := ech.NewStore(h.DB).Delete(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "clé introuvable ou active (seule une clé retirée peut être supprimée)", http.StatusNotFound)
			return
		}
		h.Log.Error("ech: suppression", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	h.push()
	w.WriteHeader(http.StatusNoContent)
}

func (h *ECHHandler) push() {
	if h.Pusher != nil {
		go h.Pusher.PushECHKeys(context.Background())
	}
}
