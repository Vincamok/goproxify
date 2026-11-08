// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/attackref"
)

// attackRef route /api/v1/security/attack-ref/… (ADR 0023, étape 1) : lecture du référentiel des attaques, rejet d'une
// entrée, lancement d'un passage du mineur.
func (h *SecurityHandler) attackRef(w http.ResponseWriter, r *http.Request, rest string) {
	if h.AttackRef == nil {
		http.Error(w, "référentiel des attaques indisponible", http.StatusServiceUnavailable)
		return
	}
	rest = strings.Trim(rest, "/")
	switch {
	case r.Method == http.MethodGet && (rest == "" || rest == "summary"):
		h.attackRefSummary(w, r)
	case r.Method == http.MethodGet && rest == "entries":
		h.attackRefEntries(w, r)
	case r.Method == http.MethodGet && rest == "dossiers":
		h.attackRefDossiers(w, r)
	case r.Method == http.MethodPost && rest == "entries/status":
		h.attackRefSetStatus(w, r)
	case r.Method == http.MethodPost && rest == "run":
		h.attackRefRun(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *SecurityHandler) attackRefSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := h.AttackRef.Store.Summary(r.Context())
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"summary": sum, "miner": h.AttackRef.Status(), "config": attackRefConfigView(h.AttackRef.Cfg)})
}

func attackRefConfigView(c attackref.Config) map[string]any {
	return map[string]any{
		"min_ips": c.MinIPs, "min_days": c.MinDays, "min_lift": c.MinLift, "max_clean_ok": c.MaxCleanOK,
		"lookback_days": int(c.Lookback.Hours() / 24), "sources": c.Sources,
	}
}

func queryInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(name))
	return n
}

func (h *SecurityHandler) attackRefEntries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	es, total, err := h.AttackRef.Store.Entries(r.Context(), attackref.EntryFilter{
		Kind: q.Get("kind"), Family: q.Get("family"), Status: q.Get("status"), Limit: queryInt(r, "limit"), Offset: queryInt(r, "offset"),
	})
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"entries": es, "total": total})
}

func (h *SecurityHandler) attackRefDossiers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := attackref.DossierFilter{Profile: q.Get("profile"), Limit: queryInt(r, "limit"), Offset: queryInt(r, "offset")}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			secJSONErr(w, errors.New("adresse IP invalide"), http.StatusBadRequest)
			return
		}
		f.IP = a.String()
	}
	if days := queryInt(r, "days"); days > 0 {
		f.Since = time.Now().AddDate(0, 0, -days)
	}
	ds, total, err := h.AttackRef.Store.Dossiers(r.Context(), f)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"dossiers": ds, "total": total})
}

func (h *SecurityHandler) attackRefSetStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	err := h.AttackRef.Store.SetStatus(r.Context(), attackref.Kind(body.Kind), body.Value, attackref.Status(body.Status))
	switch {
	case errors.Is(err, attackref.ErrBadStatus):
		secJSONErr(w, err, http.StatusBadRequest)
	case errors.Is(err, attackref.ErrNotFound):
		secJSONErr(w, err, http.StatusNotFound)
	case err != nil:
		secJSONErr(w, err, http.StatusInternalServerError)
	default:
		jsonOK(w, map[string]any{"kind": body.Kind, "value": body.Value, "status": body.Status})
	}
}

// attackRefRun lance un passage en arrière-plan : lire un mois de logs dépasse le délai d'une requête.
func (h *SecurityHandler) attackRefRun(w http.ResponseWriter, r *http.Request) {
	ctx := h.ScanCtx
	if ctx == nil {
		ctx = r.Context()
	}
	started := h.AttackRef.Trigger(ctx)
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{"started": started, "miner": h.AttackRef.Status()})
}
