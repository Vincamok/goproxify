// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/audit"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	banPreviewDefaultHours = 24
	banPreviewMaxHours     = 168
	banPreviewMaxScan      = 500_000
	banPreviewMaxIPs       = 5000
)

// RequesterIP retourne l'adresse de la personne qui appelle l'API (sans port), pour refuser une
// plage qui la couperait elle-même.
func RequesterIP(r *http.Request) string {
	v := strings.TrimSpace(audit.IPFrom(r))
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = host
	}
	return strings.Trim(v, "[]")
}

// BanTargetFromRequest valide la cible d'un ban et refuse une plage qui contient l'appelant.
func BanTargetFromRequest(r *http.Request, raw string) (security.BanTarget, error) {
	t, err := security.ParseBanTarget(raw)
	if err != nil {
		return security.BanTarget{}, err
	}
	if err := security.CheckBanLockout(t, RequesterIP(r)); err != nil {
		return security.BanTarget{}, err
	}
	return t, nil
}

// BanPreviewItem est un ban actif ou un profil IP qui recoupe la cible.
type banPreviewBan struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Source    string `json:"source"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// Relation avec la cible : « covers » (le ban contient la cible, le nouveau serait redondant),
	// « inside » (le ban est dans la cible, le nouveau l'englobe), « same » ou « overlaps ».
	Relation string `json:"relation"`
}

// banPreview : GET /api/v1/security/bans/preview?ip=<ip|cidr>&hours=24
// Mesure, sans rien créer, ce qu'un ban couperait : trafic récent de la plage, bans et profils
// qui la recoupent, et les risques (plage privée, profil allow, auto-verrouillage).
func (h *SecurityHandler) banPreview(w http.ResponseWriter, r *http.Request) {
	t, err := security.ParseBanTarget(r.URL.Query().Get("ip"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadRequest)
		return
	}
	hours := banPreviewDefaultHours
	if v, _ := strconv.Atoi(r.URL.Query().Get("hours")); v > 0 {
		hours = v
	}
	if hours > banPreviewMaxHours {
		hours = banPreviewMaxHours
	}
	res, err := BanPreview(r.Context(), h.DB, t, hours, RequesterIP(r))
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, res)
}

// BanPreview calcule l'aperçu d'impact d'un ban (voir banPreview).
func BanPreview(ctx context.Context, db *sql.DB, t security.BanTarget, hours int, requester string) (map[string]any, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	out := map[string]any{
		"target":       t.Value,
		"kind":         t.Kind(),
		"prefix_bits":  t.Prefix.Bits(),
		"addresses":    t.Addresses(),
		"hours":        hours,
		"private":      t.PrivateRange(),
		"requester":    requester,
		"requester_in": security.CheckBanLockout(t, requester) != nil,
	}

	// ── Trafic récent de la plage ─────────────────────────────────────────────
	query := `SELECT ip, status, COALESCE(waf_matches,''), COALESCE(threat_signal,'') FROM logs
	          WHERE ts >= ? AND status > 0`
	args := []any{since.Format(time.RFC3339)}
	if lo, hi, ok := security.TraceIPRange(t.Prefix); ok {
		query += ` AND ip >= ? AND ip < ?`
		args = append(args, lo, hi)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var requests, blocked, okRequests, scanned int
	ipHits, okIPs := map[string]int{}, map[string]int{}
	scanLimited := false
	for rows.Next() {
		var ip, waf, signal string
		var status int
		if rows.Scan(&ip, &status, &waf, &signal) != nil || !security.TraceMatch(t.Prefix, ip) {
			continue
		}
		if scanned++; scanned > banPreviewMaxScan {
			scanLimited = true
			break
		}
		requests++
		if _, ok := ipHits[ip]; ok || len(ipHits) < banPreviewMaxIPs {
			ipHits[ip]++
		}
		hasWAF := waf != "" && waf != "null" && waf != "[]"
		if status == 403 || status == 429 || hasWAF || signal != "" {
			blocked++
			continue
		}
		if status < 400 {
			okRequests++
			if _, ok := okIPs[ip]; ok || len(okIPs) < banPreviewMaxIPs {
				okIPs[ip]++
			}
		}
	}
	rows.Close()
	out["requests"] = requests
	out["blocked"] = blocked
	out["ok_requests"] = okRequests
	out["ips"] = len(ipHits)
	out["ok_ips"] = len(okIPs)
	out["top_ips"] = security.TopCounts(ipHits, 10)
	out["countries"] = traceCountries(ctx, db, ipHits)
	out["scan_limited"] = scanLimited

	// ── Bans actifs qui recoupent la cible ────────────────────────────────────
	bans := []banPreviewBan{}
	if br, err := db.QueryContext(ctx,
		`SELECT id, ip, source, reason, COALESCE(expires_at,'') FROM security_bans
		 WHERE expires_at IS NULL OR expires_at = '' OR datetime(expires_at) > CURRENT_TIMESTAMP`); err == nil {
		defer br.Close()
		for br.Next() {
			var b banPreviewBan
			if br.Scan(&b.ID, &b.IP, &b.Source, &b.Reason, &b.ExpiresAt) != nil {
				continue
			}
			bp, err := security.ParseTraceTarget(b.IP)
			if err != nil || !t.Prefix.Overlaps(bp) {
				continue
			}
			switch {
			case bp == t.Prefix:
				b.Relation = "same"
			case bp.Bits() <= t.Prefix.Bits() && bp.Contains(t.Prefix.Addr()):
				b.Relation = "covers"
			case t.Prefix.Bits() <= bp.Bits() && t.Prefix.Contains(bp.Addr()):
				b.Relation = "inside"
			default:
				b.Relation = "overlaps"
			}
			bans = append(bans, b)
		}
	}
	out["existing_bans"] = bans

	// ── Profils IP qui recoupent la cible (un profil allow l'emporte sur un ban) ─
	profiles := []traceProfile{}
	allowOverlap := false
	if pr, err := db.QueryContext(ctx, `SELECT id, name, mode, cidrs FROM ip_profiles WHERE enabled=1`); err == nil {
		defer pr.Close()
		for pr.Next() {
			var p traceProfile
			var cidrsJSON string
			if pr.Scan(&p.ID, &p.Name, &p.Mode, &cidrsJSON) != nil || p.ID == router.WhitelistProfileID {
				continue // la liste blanche des bans est présentée à part
			}
			var cidrs []string
			json.Unmarshal([]byte(cidrsJSON), &cidrs) //nolint:errcheck
			for _, c := range cidrs {
				if security.TraceOverlap(t.Prefix, c) {
					profiles = append(profiles, p)
					if strings.EqualFold(p.Mode, "allow") {
						allowOverlap = true
					}
					break
				}
			}
		}
	}
	out["profiles"] = profiles

	// ── Liste blanche des bans ────────────────────────────────────────────────
	wl := security.LoadWhitelist(db)
	wlOverlap := security.WhitelistOverlapping(wl, t.Prefix)
	out["whitelist"] = wlOverlap
	wlCover, wlCovered := security.WhitelistCovering(wl, t.Prefix)
	out["whitelisted"] = wlCovered

	// ── Avertissements ────────────────────────────────────────────────────────
	var warnings []string
	if t.PrivateRange() {
		warnings = append(warnings, "plage privée ou locale : la passerelle ne bloque jamais ces adresses, le ban resterait sans effet")
	}
	if out["requester_in"] == true {
		warnings = append(warnings, fmt.Sprintf("la plage contient votre adresse (%s) : le ban sera refusé", requester))
	}
	for _, b := range bans {
		switch b.Relation {
		case "same":
			warnings = append(warnings, fmt.Sprintf("déjà banni (%s, source %s)", b.IP, b.Source))
		case "covers":
			warnings = append(warnings, fmt.Sprintf("déjà couvert par le ban %s (source %s) : le nouveau ban serait redondant", b.IP, b.Source))
		}
	}
	if n := countRelation(bans, "inside"); n > 0 {
		warnings = append(warnings, fmt.Sprintf("englobe %d ban(s) existant(s) plus précis, qui deviendraient redondants", n))
	}
	if wlCovered {
		warnings = append(warnings, fmt.Sprintf("entièrement en liste blanche (%s) : le ban sera refusé", wlCover.Value))
	} else if len(wlOverlap) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d entrée(s) de la liste blanche recoupent la cible : ces adresses resteront exemptées du ban", len(wlOverlap)))
	}
	if allowOverlap {
		warnings = append(warnings, "un profil IP en mode allow recoupe cette cible : ses adresses ne seront pas bloquées malgré le ban")
	}
	switch {
	case requests == 0:
		warnings = append(warnings, fmt.Sprintf("aucun trafic de cette cible sur les %d dernières heures (ban préventif)", hours))
	case okRequests > 0:
		warnings = append(warnings, fmt.Sprintf("%d requête(s) réussie(s) de %d adresse(s) seraient coupées sur les %d dernières heures : vérifier qu'il s'agit bien d'abus", okRequests, len(okIPs), hours))
	}
	if scanLimited {
		warnings = append(warnings, "analyse limitée aux premiers résultats : les chiffres sont une borne basse")
	}
	if warnings == nil {
		warnings = []string{}
	}
	out["warnings"] = warnings
	return out, nil
}

func countRelation(bans []banPreviewBan, rel string) int {
	n := 0
	for _, b := range bans {
		if b.Relation == rel {
			n++
		}
	}
	return n
}

