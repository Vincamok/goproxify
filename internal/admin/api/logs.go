// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

// LogsHandler gère la consultation statique, l'export et le streaming SSE.
type LogsHandler struct {
	Log   *slog.Logger
	Store *logs.Store
	DB    *sql.DB
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/logs")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.list(w, r)
	case r.Method == http.MethodGet && path == "live":
		h.live(w, r)
	case r.Method == http.MethodGet && path == "export":
		h.export(w, r)
	case r.Method == http.MethodGet && path == "correlate":
		h.correlate(w, r)
	case r.Method == http.MethodGet && path == "settings":
		h.getSettings(w, r)
	case r.Method == http.MethodPut && path == "settings":
		h.putSettings(w, r)
	// RGPD : effacement par IP ou utilisateur
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "by-ip/"):
		h.deleteByIP(w, r, strings.TrimPrefix(path, "by-ip/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "by-user/"):
		h.deleteByUser(w, r, strings.TrimPrefix(path, "by-user/"))
	default:
		http.NotFound(w, r)
	}
}

func (h *LogsHandler) list(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	entries, total, err := h.Store.Search(p)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"total": total, "page": p.Page, "page_size": p.PageSize, "entries": entries})
}

func (h *LogsHandler) live(w http.ResponseWriter, r *http.Request) {
	filter := parseLogsParams(r)
	h.Store.StreamSSE(w, r, filter)
}

func (h *LogsHandler) export(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	data, ct, err := h.Store.Export(p, format)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	ts := time.Now().Format("20060102-150405")
	ext := "json"
	if format == "csv" {
		ext = "csv"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+"."+ext)
	w.Write(data) //nolint:errcheck
}

func parseLogsParams(r *http.Request) logs.SearchParams {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	return logs.SearchParams{
		Level:     q.Get("level"),
		Component: q.Get("component"),
		NodeName:  q.Get("node_name"),
		Domain:    q.Get("domain"),
		IP:        q.Get("ip"),
		Method:    q.Get("method"),
		Status:    q.Get("status"),
		Path:      q.Get("path"),
		Search:    q.Get("search"),
		DateFrom:  q.Get("date_from"),
		DateTo:    q.Get("date_to"),
		Kind:      q.Get("kind"),
		Page:      page,
		PageSize:  pageSize,
	}
}

func (h *LogsHandler) correlate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	tsStr := q.Get("ts")
	window, _ := strconv.Atoi(q.Get("window"))
	if window <= 0 {
		window = 30
	}
	at, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		at, err = time.Parse(time.RFC3339, tsStr)
		if err != nil {
			http.Error(w, "ts invalide (RFC3339 requis)", http.StatusBadRequest)
			return
		}
	}
	entries := h.Store.Correlate(domain, at, window)
	jsonOK(w, entries)
}

func (h *LogsHandler) getSettings(w http.ResponseWriter, r *http.Request) {
	parseInt := func(key string, def int) int {
		v := admindb.GetSetting(h.DB, key, "")
		if v == "" {
			return def
		}
		n := def
		strconv.Atoi(v) //nolint:errcheck
		if i, err := strconv.Atoi(v); err == nil {
			n = i
		}
		return n
	}
	accessDays, systemDays := h.Store.RetentionInfo()
	jsonOK(w, map[string]any{
		"retention_access_days":  parseInt("logs.retention_access_days", accessDays),
		"retention_system_days":  parseInt("logs.retention_system_days", systemDays),
		"defaults": map[string]any{
			"access_days": logs.DefaultRetentionAccessDays,
			"system_days": logs.DefaultRetentionSystemDays,
		},
	})
}

func (h *LogsHandler) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RetentionAccessDays int `json:"retention_access_days"`
		RetentionSystemDays int `json:"retention_system_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.RetentionAccessDays < 0 || body.RetentionSystemDays < 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.retention")
		return
	}
	if body.RetentionAccessDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_access_days", strconv.Itoa(body.RetentionAccessDays)) //nolint:errcheck
	}
	if body.RetentionSystemDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_system_days", strconv.Itoa(body.RetentionSystemDays)) //nolint:errcheck
	}
	h.Store.SetRetention(body.RetentionAccessDays, body.RetentionSystemDays)
	w.WriteHeader(http.StatusNoContent)
}

// deleteByIP supprime tous les logs d'une IP (droit à l'effacement RGPD).
func (h *LogsHandler) deleteByIP(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_ip")
		return
	}
	n, err := h.Store.DeleteByIP(ip)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"deleted": n, "ip": ip})
}

// deleteByUser supprime tous les logs d'un utilisateur (droit à l'effacement RGPD).
func (h *LogsHandler) deleteByUser(w http.ResponseWriter, r *http.Request, userID string) {
	if userID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_user")
		return
	}
	n, err := h.Store.DeleteByUserID(userID)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"deleted": n, "user_id": userID})
}

func logsJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
