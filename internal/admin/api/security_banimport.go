// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/security"
)

// Import de liste : crée des bans (ou des entrées de la liste blanche) à partir d'une liste
// d'adresses et de CIDR. Chaque entrée est validée comme à la création unitaire, les doublons et les
// cibles déjà couvertes sont ignorés, et un rapport dit pour chaque ligne ce qui a été fait. Avec
// dry_run, rien n'est écrit : on mesure d'abord l'effet.

const (
	ImportTargetBans      = "bans"
	ImportTargetWhitelist = "whitelist"

	// importMaxIssues borne les listes du rapport (les compteurs restent exacts).
	importMaxIssues = 200
	importMaxSample = 20
)

// ImportRequest est le corps de POST /security/bans/import.
type ImportRequest struct {
	Content string `json:"content"`
	// Format : auto (défaut), text, csv ou json.
	Format string `json:"format"`
	// Target : bans (défaut) ou whitelist.
	Target string `json:"target"`
	// Reason : motif des bans (ou commentaire des entrées) sans motif propre ; « import » par défaut.
	Reason string `json:"reason"`
	// Domain : domaine ciblé par les bans sans domaine propre (vide = global).
	Domain string `json:"domain"`
	// ExpiresAt : expiration RFC3339 des bans sans expiration propre ; vide = permanent.
	ExpiresAt string `json:"expires_at"`
	// Scope : passerelle ou "group:<nom>" qui appliquera les bans ; vide = toutes.
	Scope  string `json:"scope"`
	DryRun bool   `json:"dry_run"`
	// Groups résout les groupes HA pour valider Scope.
	Groups GroupResolver `json:"-"`
}

// ImportIssue situe une entrée ignorée ou rejetée.
type ImportIssue struct {
	Line   int    `json:"line"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// ImportResult est le rapport d'un import.
type ImportResult struct {
	DryRun bool   `json:"dry_run"`
	Target string `json:"target"`
	Format string `json:"format"`
	// Total : entrées lues. Created : entrées créées (ou qui le seraient en dry_run).
	Total   int `json:"total"`
	Created int `json:"created"`
	// Addresses : nombre d'adresses couvertes par les entrées créées.
	Addresses float64 `json:"addresses"`
	// Skipped : entrées valides mais sans objet (doublon, déjà couverte, en liste blanche, privée).
	// Rejected : entrées refusées (illisibles, trop larges, contenant l'appelant, expiration invalide).
	Skipped       []ImportIssue `json:"skipped"`
	SkippedCount  int           `json:"skipped_count"`
	Rejected      []ImportIssue `json:"rejected"`
	RejectedCount int           `json:"rejected_count"`
	// Sample : quelques valeurs créées, pour contrôle visuel.
	Sample []string `json:"sample"`
}

func (r *ImportResult) skip(line int, value, why string) {
	r.SkippedCount++
	if len(r.Skipped) < importMaxIssues {
		r.Skipped = append(r.Skipped, ImportIssue{line, value, why})
	}
}

func (r *ImportResult) reject(line int, value, why string) {
	r.RejectedCount++
	if len(r.Rejected) < importMaxIssues {
		r.Rejected = append(r.Rejected, ImportIssue{line, value, why})
	}
}

type importItem struct {
	line      int
	target    security.BanTarget
	reason    string
	domain    string
	expiresAt *string
}

// ImportBans analyse la liste et, hors dry_run, l'enregistre. Il ne notifie pas les passerelles :
// l'appelant le fait une fois si res.Created > 0.
func ImportBans(ctx context.Context, db *sql.DB, req ImportRequest, requester, actor string) (ImportResult, error) {
	res := ImportResult{DryRun: req.DryRun, Target: req.Target, Skipped: []ImportIssue{}, Rejected: []ImportIssue{}, Sample: []string{}}
	if res.Target == "" {
		res.Target = ImportTargetBans
	}
	if res.Target != ImportTargetBans && res.Target != ImportTargetWhitelist {
		return res, fmt.Errorf("target inconnue %q (bans ou whitelist)", req.Target)
	}
	entries, format, err := security.ParseImport(req.Content, req.Format)
	res.Format = format
	if err != nil {
		return res, err
	}
	res.Total = len(entries)
	defaultExp, err := security.NormalizeBanExpiry(req.ExpiresAt)
	if err != nil {
		return res, err
	}
	reason := req.Reason
	if reason == "" {
		reason = "import"
	}
	scope := ""
	if res.Target == ImportTargetBans {
		if scope, err = NormalizeBanScope(db, req.Groups, req.Scope); err != nil {
			return res, err
		}
	}

	whitelist := security.LoadWhitelist(db)
	var activeBans []netip.Prefix
	activeValue := map[string]string{}
	if res.Target == ImportTargetBans {
		rows, qerr := db.QueryContext(ctx,
			`SELECT ip FROM security_bans WHERE expires_at IS NULL OR expires_at = '' OR datetime(expires_at) > CURRENT_TIMESTAMP`)
		if qerr == nil {
			for rows.Next() {
				var v string
				if rows.Scan(&v) == nil {
					if p, perr := security.ParseTraceTarget(v); perr == nil {
						activeBans = append(activeBans, p)
						activeValue[p.String()] = v
					}
				}
			}
			rows.Close()
		}
	}

	var items []importItem
	seen := map[string]bool{}
	for _, e := range entries {
		t, perr := security.ParseBanTarget(e.Value)
		if perr != nil {
			res.reject(e.Line, e.Value, perr.Error())
			continue
		}
		if seen[t.Value] {
			res.skip(e.Line, t.Value, "doublon dans la liste")
			continue
		}
		seen[t.Value] = true

		if res.Target == ImportTargetWhitelist {
			if c, ok := security.WhitelistCovering(whitelist, t.Prefix); ok {
				res.skip(e.Line, t.Value, "déjà couvert par la liste blanche ("+c.Value+")")
				continue
			}
			comment := e.Reason
			if comment == "" {
				comment = reason
			}
			items = append(items, importItem{line: e.Line, target: t, reason: comment})
			continue
		}

		if lerr := security.CheckBanLockout(t, requester); lerr != nil {
			res.reject(e.Line, t.Value, lerr.Error())
			continue
		}
		if c, ok := security.WhitelistCovering(whitelist, t.Prefix); ok {
			res.skip(e.Line, t.Value, "en liste blanche ("+c.Value+")")
			continue
		}
		if t.PrivateRange() {
			res.skip(e.Line, t.Value, "plage privée ou locale : jamais bloquée par les passerelles")
			continue
		}
		covered := ""
		for _, p := range activeBans {
			if p.Bits() <= t.Prefix.Bits() && p.Contains(t.Prefix.Addr()) {
				covered = activeValue[p.String()]
				break
			}
		}
		if covered != "" {
			res.skip(e.Line, t.Value, "déjà couvert par le ban "+covered)
			continue
		}
		exp := defaultExp
		if e.ExpiresAt != "" {
			if exp, err = security.NormalizeBanExpiry(e.ExpiresAt); err != nil {
				res.reject(e.Line, t.Value, err.Error())
				continue
			}
		}
		r := e.Reason
		if r == "" {
			r = reason
		}
		d := e.Domain
		if d == "" {
			d = req.Domain
		}
		items = append(items, importItem{line: e.Line, target: t, reason: r, domain: d, expiresAt: exp})
	}

	items = dropCoveredByBatch(items, &res)
	res.Created = len(items)
	for _, it := range items {
		res.Addresses += it.target.Addresses()
		if len(res.Sample) < importMaxSample {
			res.Sample = append(res.Sample, it.target.Value)
		}
	}
	if req.DryRun || len(items) == 0 {
		return res, nil
	}

	if res.Target == ImportTargetWhitelist {
		in := make([]security.WhitelistInput, len(items))
		for i, it := range items {
			in[i] = security.WhitelistInput{Target: it.target, Comment: it.reason}
		}
		added, covered, werr := security.AddWhitelistMany(db, in, actor)
		if werr != nil {
			return res, werr
		}
		res.Created = len(added)
		res.SkippedCount += covered
		return res, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, it := range items {
		id := uuid.New().String()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at, target_scope) VALUES (?, ?, ?, ?, 'native', ?, ?)`,
			id, it.target.Value, it.domain, it.reason, it.expiresAt, scope); err != nil {
			return res, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?, ?, 'banned', ?, 'native', ?)`,
			it.target.Value, it.domain, it.reason, id); err != nil {
			return res, err
		}
	}
	return res, tx.Commit()
}

// bansImport : POST /api/v1/security/bans/import
func (h *SecurityHandler) bansImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, security.MaxImportBytes+64<<10)
	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corps JSON invalide ou trop volumineux : "+err.Error(), http.StatusBadRequest)
		return
	}
	actor := actorName(r)
	req.Groups = h.Groups
	res, err := ImportBans(r.Context(), h.DB, req, RequesterIP(r), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if res.Created > 0 && !res.DryRun {
		_, _ = h.DB.Exec(`INSERT INTO audit_log (actor, action, resource, detail) VALUES (?, 'import_bans', ?, ?)`,
			actor, "bans:"+res.Target, fmt.Sprintf("%d créé(s), %d ignoré(s), %d rejeté(s) sur %d", res.Created, res.SkippedCount, res.RejectedCount, res.Total))
		if res.Target == ImportTargetWhitelist {
			if h.OnWhitelistChange != nil {
				h.OnWhitelistChange()
			}
		} else if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	jsonOK(w, res)
}

// dropCoveredByBatch ignore les entrées déjà couvertes par une plage plus large de la même liste
// (elles seraient redondantes). Les plus larges sont examinées d'abord ; la recherche d'un ancêtre
// teste chaque longueur de préfixe possible dans l'ensemble déjà retenu.
func dropCoveredByBatch(items []importItem, res *ImportResult) []importItem {
	order := make([]int, len(items))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return items[order[a]].target.Prefix.Bits() < items[order[b]].target.Prefix.Bits()
	})
	kept := make(map[netip.Prefix]bool, len(items))
	drop := make([]bool, len(items))
	for _, idx := range order {
		p := items[idx].target.Prefix
		min := security.MinBanPrefixV6
		if p.Addr().Is4() {
			min = security.MinBanPrefixV4
		}
		for bits := min; bits < p.Bits(); bits++ {
			if anc, err := p.Addr().Prefix(bits); err == nil && kept[anc] {
				res.skip(items[idx].line, items[idx].target.Value, "couvert par "+anc.String()+" dans la même liste")
				drop[idx] = true
				break
			}
		}
		if !drop[idx] {
			kept[p] = true
		}
	}
	out := items[:0:0]
	for i, it := range items {
		if !drop[i] {
			out = append(out, it)
		}
	}
	return out
}
