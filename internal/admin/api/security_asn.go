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

	"github.com/vincamok/goproxify/internal/admin/asn"
	"github.com/vincamok/goproxify/internal/admin/security"
)

// Bannir un ASN revient à bannir l'ensemble des plages qu'il annonce : l'Admin lit ces plages dans le jeu
// de données public ip2asn et crée un ban par plage (CIDR), comme un import de liste. Les passerelles
// n'ont donc besoin d'aucune base ASN et appliquent ces bans de façon autonome. Le ban est un instantané :
// les plages annoncées plus tard s'ajoutent en relançant la même opération (les plages déjà bannies sont
// ignorées).

// ErrASNUnavailable : la base ASN n'est pas configurée ou n'a pas pu être chargée.
var ErrASNUnavailable = errors.New("base ASN indisponible")

// ErrASNUnknown : l'ASN n'annonce aucune plage dans le jeu de données.
var ErrASNUnknown = errors.New("ASN inconnu")

// ASNBanRequest est le corps de POST /security/asn/ban.
type ASNBanRequest struct {
	ASN       string `json:"asn"`
	Reason    string `json:"reason"`
	Domain    string `json:"domain"`
	ExpiresAt string `json:"expires_at"`
	// Scope : passerelle ou "group:<nom>" qui appliquera les bans ; vide = toutes.
	Scope  string `json:"scope"`
	DryRun bool   `json:"dry_run"`
}

// ASNBanResult est le rapport d'un ban d'ASN : l'identité de l'ASN et le rapport d'import de ses plages.
type ASNBanResult struct {
	ASN       uint32 `json:"asn"`
	Name      string `json:"name"`
	Country   string `json:"country"`
	Announced int    `json:"announced_ranges"`
	// Prefixes : plages (CIDR) déduites des plages annoncées. TooWide : plages trop larges pour être
	// découpées (plus de 1 024 morceaux), non bannies.
	Prefixes int `json:"prefixes"`
	TooWide  int `json:"too_wide"`
	ImportResult
}

func resolveASN(ctx context.Context, store *asn.Store, raw string) (*asn.Entry, error) {
	n, ok := asn.ParseASN(raw)
	if !ok {
		return nil, fmt.Errorf("ASN invalide %q : numéro attendu (AS16276 ou 16276)", raw)
	}
	if store == nil {
		return nil, ErrASNUnavailable
	}
	idx, err := store.Index(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrASNUnavailable, err)
	}
	e, ok := idx.Get(n)
	if !ok {
		return nil, fmt.Errorf("%w : AS%d n'annonce aucune plage", ErrASNUnknown, n)
	}
	return e, nil
}

func requesterIn(e *asn.Entry, requester string) bool {
	if a, err := netip.ParseAddr(strings.TrimSpace(requester)); err == nil {
		return e.Contains(a)
	}
	return false
}

// BanASN crée (ou, avec DryRun, simule) les bans des plages d'un ASN. Il ne notifie pas les passerelles :
// l'appelant le fait une fois si res.Created > 0 et !res.DryRun.
func BanASN(ctx context.Context, db *sql.DB, store *asn.Store, groups GroupResolver, req ASNBanRequest, requester, actor string) (ASNBanResult, error) {
	e, err := resolveASN(ctx, store, req.ASN)
	if err != nil {
		return ASNBanResult{}, err
	}
	if requesterIn(e, requester) {
		return ASNBanResult{}, security.ErrBanLockout{Target: fmt.Sprintf("AS%d", e.ASN), Requester: requester}
	}
	prefixes, tooWide := e.BanPrefixes()
	entries := make([]security.ImportEntry, len(prefixes))
	for i, p := range prefixes {
		entries[i] = security.ImportEntry{Line: i + 1, Value: p.String()}
	}
	reason := req.Reason
	if reason == "" {
		reason = "AS" + strconv.FormatUint(uint64(e.ASN), 10) + " " + e.Name
	}
	res, err := ImportBans(ctx, db, ImportRequest{
		Entries: entries, Target: ImportTargetBans,
		Reason: reason, Domain: req.Domain, ExpiresAt: req.ExpiresAt, Scope: req.Scope,
		DryRun: req.DryRun, Groups: groups, ASN: e.ASN,
	}, requester, actor)
	out := ASNBanResult{ASN: e.ASN, Name: e.Name, Country: e.Country, Announced: len(e.Ranges), Prefixes: len(prefixes), TooWide: tooWide, ImportResult: res}
	return out, err
}

// UnbanASN supprime les bans créés pour un ASN et retourne leurs plages, que l'appelant fait lever sur
// les passerelles.
func UnbanASN(ctx context.Context, db *sql.DB, number uint32) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, ip, domain, reason FROM security_bans WHERE asn=?`, number)
	if err != nil {
		return nil, err
	}
	type ban struct{ id, ip, domain, reason string }
	var bans []ban
	for rows.Next() {
		var b ban
		if rows.Scan(&b.id, &b.ip, &b.domain, &b.reason) == nil {
			bans = append(bans, b)
		}
	}
	rows.Close()
	if len(bans) == 0 {
		return nil, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	ips := make([]string, 0, len(bans))
	for _, b := range bans {
		if _, err := tx.ExecContext(ctx, `DELETE FROM security_bans WHERE id=?`, b.id); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?, ?, 'unbanned', ?, 'native', ?)`,
			b.ip, b.domain, b.reason, b.id); err != nil {
			return nil, err
		}
		ips = append(ips, b.ip)
	}
	return ips, tx.Commit()
}

// ASNInfo est une ligne de résultat de recherche.
type ASNInfo struct {
	ASN       uint32  `json:"asn"`
	Name      string  `json:"name"`
	Country   string  `json:"country"`
	Ranges    int     `json:"ranges"`
	V4Addrs   float64 `json:"v4_addresses"`
	V6Ranges  int     `json:"v6_ranges"`
	BannedNow int     `json:"banned_ranges"`
}

func asnInfo(db *sql.DB, e *asn.Entry) ASNInfo {
	in := ASNInfo{ASN: e.ASN, Name: e.Name, Country: e.Country, Ranges: len(e.Ranges), V4Addrs: e.V4Addresses(), V6Ranges: e.V6Ranges()}
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE asn=?`, e.ASN).Scan(&in.BannedNow)
	return in
}

// LookupASN cherche par numéro (AS16276, 16276), par adresse IP (l'ASN qui l'annonce) ou par nom.
func LookupASN(ctx context.Context, db *sql.DB, store *asn.Store, q string) ([]ASNInfo, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, fmt.Errorf("q requis (numéro d'ASN, adresse IP ou nom)")
	}
	if store == nil {
		return nil, ErrASNUnavailable
	}
	idx, err := store.Index(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrASNUnavailable, err)
	}
	out := []ASNInfo{}
	if a, err := netip.ParseAddr(q); err == nil {
		if e, ok := idx.ByIP(a); ok {
			out = append(out, asnInfo(db, e))
		}
		return out, nil
	}
	if n, ok := asn.ParseASN(q); ok {
		if e, ok := idx.Get(n); ok {
			out = append(out, asnInfo(db, e))
		}
		return out, nil
	}
	for _, e := range idx.Search(q, 20) {
		out = append(out, asnInfo(db, e))
	}
	return out, nil
}

// ASNPreview mesure l'effet d'un ban d'ASN sans rien créer : trafic récent venant de l'ASN et rapport de
// simulation des bans (plages créées, ignorées, rejetées).
func ASNPreview(ctx context.Context, db *sql.DB, store *asn.Store, groups GroupResolver, raw string, hours int, requester string) (map[string]any, error) {
	e, err := resolveASN(ctx, store, raw)
	if err != nil {
		return nil, err
	}
	sim, err := BanASN(ctx, db, store, groups, ASNBanRequest{ASN: raw, DryRun: true}, requester, "")
	var lockout security.ErrBanLockout
	inASN := errors.As(err, &lockout)
	if err != nil && !inASN {
		return nil, err
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.QueryContext(ctx, `SELECT ip, status, COALESCE(waf_matches,''), COALESCE(threat_signal,'') FROM logs WHERE ts >= ? AND status > 0`, since.Format(time.RFC3339))
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
		if rows.Scan(&ip, &status, &waf, &signal) != nil {
			continue
		}
		a, perr := netip.ParseAddr(ip)
		if perr != nil || !e.Contains(a) {
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

	var warnings []string
	if inASN {
		warnings = append(warnings, fmt.Sprintf("l'ASN contient votre adresse (%s) : le ban sera refusé", requester))
	}
	if sim.TooWide > 0 {
		warnings = append(warnings, fmt.Sprintf("%d plage(s) annoncée(s) trop larges pour être découpées : elles ne seront pas bannies", sim.TooWide))
	}
	if sim.Created == 0 && sim.RejectedCount == 0 && sim.SkippedCount > 0 {
		warnings = append(warnings, "toutes les plages de cet ASN sont déjà bannies, en liste blanche ou privées")
	}
	if sim.SkippedCount > 0 && sim.Created > 0 {
		warnings = append(warnings, fmt.Sprintf("%d plage(s) ignorée(s) (déjà bannies, en liste blanche ou privées)", sim.SkippedCount))
	}
	switch {
	case requests == 0:
		warnings = append(warnings, fmt.Sprintf("aucun trafic de cet ASN sur les %d dernières heures (ban préventif)", hours))
	case okRequests > 0:
		warnings = append(warnings, fmt.Sprintf("%d requête(s) réussie(s) de %d adresse(s) seraient coupées sur les %d dernières heures : vérifier qu'il s'agit bien d'abus", okRequests, len(okIPs), hours))
	}
	if scanLimited {
		warnings = append(warnings, "analyse limitée aux premiers résultats : les chiffres sont une borne basse")
	}
	if warnings == nil {
		warnings = []string{}
	}
	return map[string]any{
		"asn": asnInfo(db, e), "hours": hours, "requester_in": inASN,
		"prefixes": sim.Prefixes, "too_wide": sim.TooWide, "would_create": sim.Created,
		"skipped_count": sim.SkippedCount, "rejected_count": sim.RejectedCount, "skipped": sim.Skipped, "rejected": sim.Rejected,
		"requests": requests, "blocked": blocked, "ok_requests": okRequests, "ips": len(ipHits), "ok_ips": len(okIPs),
		"top_ips": security.TopCounts(ipHits, 10), "countries": traceCountries(ctx, db, ipHits),
		"scan_limited": scanLimited, "warnings": warnings,
	}, nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func asnStatus(err error) int {
	var lockout security.ErrBanLockout
	switch {
	case errors.As(err, &lockout):
		return http.StatusConflict
	case errors.Is(err, ErrASNUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrASNUnknown):
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// asnRoute dispatche /api/v1/security/asn[/…]. id : "" (recherche), info, refresh, preview, ban.
func (h *SecurityHandler) asnRoute(w http.ResponseWriter, r *http.Request, id string) {
	switch {
	case r.Method == http.MethodGet && id == "":
		h.asnLookup(w, r)
	case r.Method == http.MethodGet && id == "info":
		if h.ASN == nil {
			secJSONErr(w, ErrASNUnavailable, http.StatusServiceUnavailable)
			return
		}
		jsonOK(w, h.ASN.Info())
	case r.Method == http.MethodPost && id == "refresh":
		if h.ASN == nil {
			secJSONErr(w, ErrASNUnavailable, http.StatusServiceUnavailable)
			return
		}
		if err := h.ASN.Refresh(r.Context()); err != nil {
			secJSONErr(w, fmt.Errorf("mise à jour de la base ASN impossible : %w", err), http.StatusBadGateway)
			return
		}
		jsonOK(w, h.ASN.Info())
	case r.Method == http.MethodGet && id == "preview":
		h.asnPreview(w, r)
	case r.Method == http.MethodPost && id == "ban":
		h.asnBan(w, r)
	case r.Method == http.MethodDelete && id == "ban":
		h.asnUnban(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *SecurityHandler) asnLookup(w http.ResponseWriter, r *http.Request) {
	res, err := LookupASN(r.Context(), h.DB, h.ASN, r.URL.Query().Get("q"))
	if err != nil {
		secJSONErr(w, err, asnStatus(err))
		return
	}
	jsonOK(w, res)
}

func (h *SecurityHandler) asnPreview(w http.ResponseWriter, r *http.Request) {
	hours := banPreviewDefaultHours
	if v, _ := strconv.Atoi(r.URL.Query().Get("hours")); v > 0 {
		hours = v
	}
	if hours > banPreviewMaxHours {
		hours = banPreviewMaxHours
	}
	res, err := ASNPreview(r.Context(), h.DB, h.ASN, h.Groups, r.URL.Query().Get("asn"), hours, RequesterIP(r))
	if err != nil {
		secJSONErr(w, err, asnStatus(err))
		return
	}
	jsonOK(w, res)
}

func (h *SecurityHandler) asnBan(w http.ResponseWriter, r *http.Request) {
	var req ASNBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	actor := actorName(r)
	res, err := BanASN(r.Context(), h.DB, h.ASN, h.Groups, req, RequesterIP(r), actor)
	if err != nil {
		secJSONErr(w, err, asnStatus(err))
		return
	}
	if res.Created > 0 && !res.DryRun {
		_, _ = h.DB.Exec(`INSERT INTO audit_log (actor, action, resource, detail) VALUES (?, 'ban_asn', ?, ?)`,
			actor, fmt.Sprintf("asn:%d", res.ASN), fmt.Sprintf("%s : %d plage(s) bannie(s), %d ignorée(s), %d rejetée(s)", res.Name, res.Created, res.SkippedCount, res.RejectedCount))
		if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	jsonOK(w, res)
}

func (h *SecurityHandler) asnUnban(w http.ResponseWriter, r *http.Request) {
	n, ok := asn.ParseASN(r.URL.Query().Get("asn"))
	if !ok {
		http.Error(w, "asn requis (numéro d'ASN)", http.StatusBadRequest)
		return
	}
	ips, err := UnbanASN(r.Context(), h.DB, n)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if len(ips) > 0 {
		_, _ = h.DB.Exec(`INSERT INTO audit_log (actor, action, resource, detail) VALUES (?, 'unban_asn', ?, ?)`,
			actorName(r), fmt.Sprintf("asn:%d", n), fmt.Sprintf("%d plage(s) débannie(s)", len(ips)))
		if h.OnUnbanMany != nil {
			h.OnUnbanMany(ips)
		} else if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	jsonOK(w, map[string]any{"asn": n, "removed": len(ips)})
}
