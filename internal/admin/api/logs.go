// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"log/slog"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// LogsSettingsPusher pousse les settings de logging vers les passerelles.
type LogsSettingsPusher interface {
	PushIPProtection(ctx context.Context, anonymize, pseudonymize bool)
}

// LogsHandler gère la consultation statique, l'export et le streaming SSE.
type LogsHandler struct {
	Log    *slog.Logger
	Store  *logs.Store
	DB     *sql.DB
	Pusher LogsSettingsPusher
	// OnUnban (optionnel) lève les bans d'une IP sur les passerelles : l'effacement RGPD d'une IP
	// supprime ses bans de la base Admin.
	OnUnban func(ip string)
	// OnEraseIP (optionnel) efface l'IP des passerelles : access log et historique des bans.
	OnEraseIP func(ip string)
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/logs")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.list(w, r)
	case r.Method == http.MethodGet && path == "facets":
		h.facets(w, r)
	case r.Method == http.MethodGet && path == "histogram":
		h.histogram(w, r)
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
	// RGPD : révélation IP pseudonymisée (scope gdpr:reveal requis)
	case r.Method == http.MethodPost && path == "reveal-ip":
		h.revealIP(w, r)
	// RGPD : export d'accès et de portabilité (Art. 15 et 20), par IP ou par compte
	case r.Method == http.MethodPost && path == "subject-export":
		h.subjectExport(w, r)
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
	entries, hasMore, err := h.Store.Search(p)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var lastID int64
	if len(entries) > 0 {
		lastID = entries[len(entries)-1].ID
	}
	h.attachCountries(entries)
	jsonOK(w, map[string]any{"has_more": hasMore, "last_id": lastID, "page": p.Page, "page_size": p.PageSize, "entries": entries})
}

// attachCountries renseigne Entry.Country depuis le cache geoip_cache déjà alimenté
// par le GeoResolver (dashboard/Prism/bans) — même source, même limite : une IP non
// encore résolue reste vide (pas d'appel réseau synchrone depuis cette route).
func (h *LogsHandler) attachCountries(entries []logs.Entry) {
	if h.DB == nil || len(entries) == 0 {
		return
	}
	ips := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e.IP != "" {
			ips[e.IP] = struct{}{}
		}
	}
	if len(ips) == 0 {
		return
	}
	args := make([]any, 0, len(ips))
	placeholders := make([]string, 0, len(ips))
	for ip := range ips {
		placeholders = append(placeholders, "?")
		args = append(args, ip)
	}
	rows, err := h.DB.Query(
		`SELECT ip, country_code FROM geoip_cache WHERE ip IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	cc := make(map[string]string, len(ips))
	for rows.Next() {
		var ip, code string
		if rows.Scan(&ip, &code) == nil && code != "" && code != "XX" {
			cc[ip] = code
		}
	}
	for i := range entries {
		entries[i].Country = cc[entries[i].IP]
	}
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

// facets : mêmes filtres que la liste, plus fields=level,component,node_name,domain,method (défaut : tous).
func (h *LogsHandler) facets(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	fields := []string{"level", "component", "node_name", "domain", "method"}
	if v := r.URL.Query().Get("fields"); v != "" {
		fields = strings.Split(v, ",")
	}
	out, err := h.Store.Facets(p, fields)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, out)
}

// histogram : mêmes filtres que la liste, plus bucket=minute|hour|day (défaut selon l'étendue ; 24 h si aucune date).
func (h *LogsHandler) histogram(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	now := time.Now()
	from, to := now.Add(-24*time.Hour), now
	if t, err := time.Parse(time.RFC3339, p.DateFrom); err == nil {
		from = t
	} else {
		p.DateFrom = from.UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.RFC3339, p.DateTo); err == nil {
		to = t
	}
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "hour"
		if to.Sub(from) <= 6*time.Hour {
			bucket = "minute"
		}
	}
	pts, err := h.Store.Histogram(p, bucket)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"bucket": bucket, "points": pts})
}

func parseLogsParams(r *http.Request) logs.SearchParams {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	beforeID, _ := strconv.ParseInt(q.Get("before_id"), 10, 64)
	return logs.SearchParams{
		Level:           q.Get("level"),
		Component:       q.Get("component"),
		NodeName:        q.Get("node_name"),
		NodeID:          q.Get("node_id"),
		Domain:          q.Get("domain"),
		IP:              q.Get("ip"),
		Method:          q.Get("method"),
		Status:          q.Get("status"),
		Path:            q.Get("path"),
		TLSJA3:          q.Get("tls_ja3"),
		TLSJA4:          q.Get("tls_ja4"),
		Search:          q.Get("search"),
		DateFrom:        q.Get("date_from"),
		DateTo:          q.Get("date_to"),
		Kind:            q.Get("kind"),
		ExcludeInternal: q.Get("exclude_internal") == "1" || q.Get("exclude_internal") == "true",
		Page:            page,
		PageSize:        pageSize,
		BeforeID:        beforeID,
	}
}

func (h *LogsHandler) correlate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	requestID := q.Get("request_id")
	if requestID != "" {
		jsonOK(w, h.Store.CorrelateByRequestID(requestID))
		return
	}
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
	jsonOK(w, h.Store.Correlate(domain, at, window))
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
	ipAnonymize := admindb.GetSetting(h.DB, "logs.ip_anonymize", "false") == "true"
	ipPseudonymize := admindb.GetSetting(h.DB, "logs.ip_pseudonymize", "false") == "true"
	jsonOK(w, map[string]any{
		"retention_access_days": parseInt("logs.retention_access_days", accessDays),
		"retention_system_days": parseInt("logs.retention_system_days", systemDays),
		"retention_ban_days":    parseInt("logs.retention_ban_days", h.Store.BanRetentionDays()),
		"ip_anonymize":          ipAnonymize,
		"ip_pseudonymize":       ipPseudonymize,
		"defaults": map[string]any{
			"access_days": logs.DefaultRetentionAccessDays,
			"system_days": logs.DefaultRetentionSystemDays,
			"ban_days":    logs.DefaultRetentionBanDays,
		},
	})
}

func (h *LogsHandler) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RetentionAccessDays int   `json:"retention_access_days"`
		RetentionSystemDays int   `json:"retention_system_days"`
		RetentionBanDays    int   `json:"retention_ban_days"`
		IPAnonymize        *bool `json:"ip_anonymize,omitempty"`
		IPPseudonymize      *bool `json:"ip_pseudonymize,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.RetentionAccessDays < 0 || body.RetentionSystemDays < 0 || body.RetentionBanDays < 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.retention")
		return
	}
	prevAnon := admindb.GetSetting(h.DB, "logs.ip_anonymize", "false") == "true"
	prevPseudo := admindb.GetSetting(h.DB, "logs.ip_pseudonymize", "false") == "true"
	anon, pseudo := prevAnon, prevPseudo
	if body.IPAnonymize != nil {
		anon = *body.IPAnonymize
	}
	if body.IPPseudonymize != nil {
		pseudo = *body.IPPseudonymize
	}
	if anon && pseudo {
		writeErr(w, r, http.StatusBadRequest, "api.err.ip_mode_conflict")
		return
	}
	if body.RetentionAccessDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_access_days", strconv.Itoa(body.RetentionAccessDays)) //nolint:errcheck
	}
	if body.RetentionSystemDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_system_days", strconv.Itoa(body.RetentionSystemDays)) //nolint:errcheck
	}
	if body.RetentionBanDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_ban_days", strconv.Itoa(body.RetentionBanDays)) //nolint:errcheck
	}
	h.Store.SetRetention(body.RetentionAccessDays, body.RetentionSystemDays)
	h.Store.SetBanRetention(body.RetentionBanDays)
	actor := adminauth.UserIDFromContext(r.Context())
	if anon != prevAnon {
		admindb.SetSetting(h.DB, "logs.ip_anonymize", strconv.FormatBool(anon)) //nolint:errcheck
		_ = admindb.WriteAudit(h.DB, actor, "logs_ip_anonymize", "logs", fmt.Sprintf("enabled=%t", anon))
	}
	if pseudo != prevPseudo {
		admindb.SetSetting(h.DB, "logs.ip_pseudonymize", strconv.FormatBool(pseudo)) //nolint:errcheck
		_ = admindb.WriteAudit(h.DB, actor, "logs_ip_pseudonymize", "logs", fmt.Sprintf("enabled=%t", pseudo))
		h.Store.SetPseudonymize(pseudo)
	}
	if (anon != prevAnon || pseudo != prevPseudo) && h.Pusher != nil {
		h.Pusher.PushIPProtection(r.Context(), anon, pseudo)
	}
	w.WriteHeader(http.StatusNoContent)
}

// revealIP retourne l'IP réelle d'une entrée pseudonymisée.
// Nécessite le scope gdpr:reveal. Un motif (reason) est obligatoire. Chaque appel est audité.
func (h *LogsHandler) revealIP(w http.ResponseWriter, r *http.Request) {
	if !rbac.EffectiveHasScope(r.Context(), h.DB, rbac.ScopeGDPRReveal) {
		writeErr(w, r, http.StatusForbidden, "api.err.gdpr_reveal_forbidden")
		return
	}
	var body struct {
		EntryID int64  `json:"entry_id"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.EntryID <= 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_entry_id")
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.reason_required")
		return
	}
	ip, err := h.Store.RevealIP(body.EntryID)
	switch {
	case errors.Is(err, logs.ErrEntryNotFound):
		logsJSONErr(w, err, http.StatusNotFound)
		return
	case errors.Is(err, logs.ErrNotPseudonymized):
		logsJSONErr(w, err, http.StatusUnprocessableEntity)
		return
	case err != nil:
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	detail := fmt.Sprintf("entry_id=%d reason=%q", body.EntryID, body.Reason)
	_ = admindb.WriteAudit(h.DB, actor, "gdpr_reveal_ip", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "warn",
		Component: "admin",
		Message:   fmt.Sprintf("RGPD révélation IP entrée #%d par %s — %s", body.EntryID, actor, body.Reason),
	})
	jsonOK(w, map[string]any{
		"entry_id":     body.EntryID,
		"ip":           ip,
		"requested_by": actor,
		"reason":       body.Reason,
		"ts":           time.Now().UTC().Format(time.RFC3339),
	})
}

// deleteByIP supprime tous les logs d'une IP (droit à l'effacement RGPD).
// Body JSON optionnel : {"reason": "demande RGPD article 17"}
func (h *LogsHandler) deleteByIP(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_ip")
		return
	}
	// Une valeur non-IP (« [pseudonymisé] ») effacerait d'un coup toutes les entrées pseudonymisées.
	if _, err := netip.ParseAddr(ip); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.invalid_ip")
		return
	}
	reason := parseDeletionReason(r)
	actor := adminauth.UserIDFromContext(r.Context())

	res, err := h.Store.EraseIP(ip)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	// Les passerelles gardent leur copie des bans, y compris ceux qu'elles ont posés elles-mêmes.
	if h.OnUnban != nil {
		h.OnUnban(ip)
	}
	if h.OnEraseIP != nil {
		h.OnEraseIP(ip)
	}

	// Trace de l'effacement sans réinscrire l'IP effacée en clair (audit et logs système).
	ref := h.Store.IPReference(ip)
	detail := fmt.Sprintf("ip=%s deleted=%d bans=%d ban_history=%d geoip_cache=%d audit_ip=%d reason=%q",
		ref, res.Logs, res.Bans, res.BanHistory, res.GeoCache, res.AuditIP, reason)
	_ = admindb.WriteAudit(h.DB, actor, "rgpd_erasure_ip", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "info",
		Component: "admin",
		Message: fmt.Sprintf("RGPD effacement IP %s : %d entrées de logs, %d bans, %d événements de ban, %d entrées GeoIP supprimés par %s — %s",
			ref, res.Logs, res.Bans, res.BanHistory, res.GeoCache, actor, reason),
	})

	jsonOK(w, map[string]any{
		"deleted":             res.Logs,
		"bans_deleted":        res.Bans,
		"ban_history_deleted": res.BanHistory,
		"geoip_cache_deleted": res.GeoCache,
		"audit_ip_cleared":    res.AuditIP,
		"ip":                  ip,
	})
}

// deleteByUser supprime tous les logs d'un utilisateur (droit à l'effacement RGPD).
// Body JSON optionnel : {"reason": "demande RGPD article 17"}
func (h *LogsHandler) deleteByUser(w http.ResponseWriter, r *http.Request, userID string) {
	if userID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_user")
		return
	}
	reason := parseDeletionReason(r)
	actor := adminauth.UserIDFromContext(r.Context())

	n, err := h.Store.DeleteByUserID(userID)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}

	detail := fmt.Sprintf("user_id=%s deleted=%d reason=%q", userID, n, reason)
	_ = admindb.WriteAudit(h.DB, actor, "rgpd_erasure_user", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "info",
		Component: "admin",
		Message:   fmt.Sprintf("RGPD effacement utilisateur %s : %d entrées supprimées par %s — %s", userID, n, actor, reason),
	})

	jsonOK(w, map[string]any{"deleted": n, "user_id": userID})
}

// parseDeletionReason lit le champ "reason" du body JSON (optionnel).
func parseDeletionReason(r *http.Request) string {
	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	if body.Reason == "" {
		return "non précisé"
	}
	return body.Reason
}

func logsJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}

// subjectExport rend ce que l'Admin garde d'une IP ou d'un compte (RGPD Art. 15 et 20), en JSON à
// télécharger. L'IP voyage dans le corps, pas dans l'URL ; l'audit n'en garde que l'empreinte.
// Body JSON : {"ip": "…"} ou {"user_id": "…"}, plus un "reason" facultatif.
func (h *LogsHandler) subjectExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP     string `json:"ip"`
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if (body.IP == "") == (body.UserID == "") {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_subject")
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "non précisé"
	}
	actor := adminauth.UserIDFromContext(r.Context())

	var out any
	var detail, action, name string
	if body.IP != "" {
		if _, err := netip.ParseAddr(body.IP); err != nil {
			writeErr(w, r, http.StatusBadRequest, "api.err.invalid_ip")
			return
		}
		res, err := h.Store.ExportIP(body.IP)
		if err != nil {
			logsJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		out, action, name = res, "rgpd_export_ip", "ip"
		detail = fmt.Sprintf("ip=%s logs=%d bans=%d ban_history=%d audit=%d reason=%q",
			h.Store.IPReference(body.IP), len(res.Logs), len(res.Bans), len(res.BanHistory), len(res.Audit), reason)
	} else {
		res, err := h.Store.ExportUser(body.UserID)
		if err != nil {
			logsJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		out, action, name = res, "rgpd_export_user", "user"
		detail = fmt.Sprintf("user_id=%s logs=%d audit=%d reason=%q", body.UserID, len(res.Logs), len(res.Audit), reason)
	}
	_ = admindb.WriteAudit(h.DB, actor, action, "logs", detail)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="rgpd-export-`+name+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck
}
