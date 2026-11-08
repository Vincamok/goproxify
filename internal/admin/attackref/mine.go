// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

// Config règle le mineur. Les valeurs de départ (ADR 0023, section 3) n'ont jamais été calibrées sur un parc réel.
type Config struct {
	MinIPs      int           // IP bannies distinctes qui doivent avoir fait la même chose (5)
	MinDays     int           // jours de ban distincts (2)
	MinLift     float64       // rapport entre la part du trafic banni et celle du trafic non banni (50)
	MaxCleanOK  int64         // réponses réussies d'IP non bannies au-delà desquelles un chemin est visité par des visiteurs (3)
	Lookback    time.Duration // période relue pour les dossiers et pour mesurer le trafic légitime (30 jours)
	Before      time.Duration // activité relue avant le ban (24 h)
	After       time.Duration // activité relue après le ban (1 h)
	MaxPerRun   int           // dossiers construits par passage (200)
	Sources     []string      // sources de ban dont on apprend : celles qui détectent seules
	MaxDossiers time.Duration // rétention des dossiers (365 jours)
}

// DefaultConfig rend les valeurs de départ.
func DefaultConfig() Config {
	return Config{
		MinIPs: 5, MinDays: 2, MinLift: 50, MaxCleanOK: 3,
		Lookback: 30 * 24 * time.Hour, Before: 24 * time.Hour, After: time.Hour, MaxPerRun: 200,
		Sources:     []string{"fail2ban", "threat", "waf", "rules_engine"},
		MaxDossiers: 365 * 24 * time.Hour,
	}
}

// Reach est le trafic de toutes les IP sur un préfixe de chemin.
type Reach struct {
	Requests int64
	// OK : requêtes réussies (statut < 400) et non signalées.
	OK int64
}

// Traffic est ce que le mineur lit des logs.
type Traffic interface {
	// Lines rend les lignes d'accès d'une IP sur la période.
	Lines(ctx context.Context, ip string, from, to time.Time) ([]Line, error)
	// PathReach rend le trafic de toutes les IP sur les chemins qui commencent par prefix.
	PathReach(ctx context.Context, prefix string, from, to time.Time) (Reach, error)
	// TotalRequests rend le nombre de requêtes d'accès de la période.
	TotalRequests(ctx context.Context, from, to time.Time) (int64, error)
}

// Miner construit les dossiers et recalcule les entrées.
type Miner struct {
	Store   *Store
	Traffic Traffic
	Cfg     Config
	Now     func() time.Time

	mu      sync.Mutex
	stateMu sync.Mutex
	running bool
	last    Result
	lastAt  time.Time
	lastErr string
}

// Result dit ce qu'un passage a fait.
type Result struct {
	DossiersBuilt int `json:"dossiers_built"`
	Skipped       int `json:"skipped"`
	Entries       int `json:"entries"`
	Dropped       int `json:"dropped"`
	Errors        int `json:"errors"`
	// Degraded : les passerelles n'ont pas toutes répondu ; les entrées de chemin n'ont pas été recalculées.
	Degraded bool   `json:"degraded,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (m *Miner) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// run construit les dossiers des bans qui n'en ont pas encore, puis recalcule les entrées. Deux passages ne se
// chevauchent pas : le second attend le premier.
func (m *Miner) run(ctx context.Context) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res Result
	now := m.now()
	bans, err := m.listBans(ctx, now.Add(-m.Cfg.Lookback))
	if err != nil {
		return res, err
	}
	for _, b := range bans {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if res.DossiersBuilt >= m.Cfg.MaxPerRun {
			break
		}
		// Le dossier attend la fin de la fenêtre d'après-ban : ce que l'IP tente encore une fois bannie en fait partie.
		if b.At.Add(m.Cfg.After).After(now) || !eligibleIP(b.IP) {
			res.Skipped++
			continue
		}
		if has, err := m.Store.HasDossier(ctx, b.IP, b.At); err != nil {
			return res, err
		} else if has {
			continue
		}
		if m.contested(ctx, b) {
			res.Skipped++
			continue
		}
		lines, err := m.Traffic.Lines(ctx, b.IP, b.At.Add(-m.Cfg.Before), b.At.Add(m.Cfg.After))
		if err != nil {
			res.Errors++
			continue
		}
		if err := m.Store.SaveDossier(ctx, BuildDossier(b, lines)); err != nil {
			return res, err
		}
		res.DossiersBuilt++
	}
	if m.Cfg.MaxDossiers > 0 {
		if _, err := m.Store.PurgeDossiersBefore(ctx, now.Add(-m.Cfg.MaxDossiers)); err != nil {
			return res, err
		}
	}
	return res, m.recompute(ctx, &res)
}

// eligibleIP écarte ce qui ne peut pas être un attaquant extérieur : plages de ban, adresses privées, de boucle locale.
func eligibleIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback()
}

func (m *Miner) listBans(ctx context.Context, since time.Time) ([]BanInfo, error) {
	if len(m.Cfg.Sources) == 0 {
		return nil, nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(m.Cfg.Sources)), ",")
	args := []any{sqltime.Format(since)}
	for _, s := range m.Cfg.Sources {
		args = append(args, s)
	}
	rows, err := m.Store.DB.QueryContext(ctx,
		`SELECT ip, created_at, source, reason, user_agent, signals FROM security_ban_history
		 WHERE action='banned' AND created_at >= ? AND source IN (`+marks+`) AND instr(ip, '/') = 0 ORDER BY created_at ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BanInfo
	for rows.Next() {
		var b BanInfo
		var at, signals string
		if err := rows.Scan(&b.IP, &at, &b.Source, &b.Reason, &b.UserAgent, &signals); err != nil {
			return nil, err
		}
		t, err := sqltime.Parse(at)
		if err != nil {
			continue
		}
		b.At = t.UTC()
		b.Signals = signalNames(signals)
		out = append(out, b)
	}
	return out, rows.Err()
}

func signalNames(raw string) []string {
	if raw == "" {
		return nil
	}
	var in []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal([]byte(raw), &in) != nil {
		return nil
	}
	var out []string
	for _, s := range in {
		if s.Name != "" {
			out = append(out, s.Name)
		}
	}
	return out
}

// contested : un déban autre que l'expiration, après le ban, laisse penser à un faux positif ; une IP contestée
// n'enseigne rien.
func (m *Miner) contested(ctx context.Context, b BanInfo) bool {
	var n int
	err := m.Store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM security_ban_history WHERE ip=? AND action='unbanned' AND created_at > ? AND lower(reason) NOT LIKE '%expir%'`,
		b.IP, sqltime.Format(b.At)).Scan(&n)
	return err == nil && n > 0
}

type aggregate struct {
	ips      map[string]struct{}
	days     map[string]struct{}
	hits     int
	okHits   int
	first    time.Time
	last     time.Time
	families map[Family]int
	sample   string
}

func newAggregate() *aggregate {
	return &aggregate{ips: map[string]struct{}{}, days: map[string]struct{}{}, families: map[Family]int{}}
}

func (a *aggregate) add(d *Dossier, hits, ok int, first, last time.Time, f Family, sample string) {
	a.ips[d.IP] = struct{}{}
	a.days[d.BannedAt.Format("2006-01-02")] = struct{}{}
	a.hits += hits
	a.okHits += ok
	if a.first.IsZero() || (!first.IsZero() && first.Before(a.first)) {
		a.first = first
	}
	if last.After(a.last) {
		a.last = last
	}
	a.families[f] += hits
	if a.sample == "" {
		a.sample = sample
	}
}

func (a *aggregate) family() Family {
	best, n := FamilyUnclassified, -1
	for f, c := range a.families {
		if c > n || (c == n && f < best) {
			best, n = f, c
		}
	}
	return best
}

func (m *Miner) recompute(ctx context.Context, res *Result) error {
	now := m.now()
	since := now.Add(-m.Cfg.Lookback)
	dossiers, _, err := m.Store.Dossiers(ctx, DossierFilter{Since: since, Limit: 500})
	if err != nil {
		return err
	}
	// Dossiers lit par pages de 500 : le référentiel d'une installation tient dans quelques pages.
	for off := 500; ; off += 500 {
		page, _, err := m.Store.Dossiers(ctx, DossierFilter{Since: since, Limit: 500, Offset: off})
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		dossiers = append(dossiers, page...)
	}

	paths, uas := map[string]*aggregate{}, map[string]*aggregate{}
	bannedTotal := 0
	for i := range dossiers {
		d := &dossiers[i]
		bannedTotal += d.Requests
		for _, p := range d.Paths {
			ok := 0
			for code, n := range p.Statuses {
				if len(code) == 3 && code[0] != '4' && code[0] != '5' {
					ok += n
				}
			}
			a := paths[p.Template]
			if a == nil {
				a = newAggregate()
				paths[p.Template] = a
			}
			a.add(d, p.Count, ok, p.First, p.Last, p.Family, p.Sample)
		}
		if d.UAFamily != "" {
			a := uas[d.UAFamily]
			if a == nil {
				a = newAggregate()
				uas[d.UAFamily] = a
			}
			a.add(d, 1, 0, d.BannedAt, d.BannedAt, FamilyOffensiveClient, clip(d.UserAgent, maxSample))
		}
	}
	enough := func(a *aggregate) bool { return len(a.ips) >= m.Cfg.MinIPs && len(a.days) >= m.Cfg.MinDays }

	keepUA := map[string]struct{}{}
	for v, a := range uas {
		if !enough(a) {
			continue
		}
		if err := m.Store.upsertEntry(ctx, entryOf(KindUA, v, a, LiftUnmeasured, 0)); err != nil {
			return err
		}
		keepUA[v] = struct{}{}
		res.Entries++
	}
	n, err := m.Store.dropStale(ctx, KindUA, keepUA)
	if err != nil {
		return err
	}
	res.Dropped += n

	var candidates []string
	for tpl, a := range paths {
		if enough(a) && !Protected(tpl) && Specific(tpl) {
			candidates = append(candidates, tpl)
		}
	}
	if len(candidates) == 0 {
		n, err := m.Store.dropStale(ctx, KindPath, map[string]struct{}{})
		res.Dropped += n
		return err
	}
	total, err := m.Traffic.TotalRequests(ctx, since, now)
	if err != nil {
		res.Degraded, res.Message = true, "passerelles injoignables : les entrées de chemin n'ont pas été recalculées"
		return nil
	}
	cleanTotal := total - int64(bannedTotal)
	if cleanTotal < 0 {
		cleanTotal = 0
	}
	keep := map[string]struct{}{}
	for _, tpl := range candidates {
		a := paths[tpl]
		reach, err := m.Traffic.PathReach(ctx, LiteralPrefix(tpl), since, now)
		if err != nil {
			res.Degraded, res.Message = true, "passerelles injoignables : les entrées de chemin n'ont pas été recalculées"
			return nil
		}
		cleanHits := max(0, reach.Requests-int64(a.hits))
		cleanOK := max(0, reach.OK-int64(a.okHits))
		if cleanOK >= m.Cfg.MaxCleanOK || bannedTotal == 0 {
			continue
		}
		bannedShare := float64(a.hits) / float64(bannedTotal)
		cleanShare := float64(cleanHits+1) / float64(cleanTotal+1)
		lift := bannedShare / cleanShare
		if lift < m.Cfg.MinLift {
			continue
		}
		if err := m.Store.upsertEntry(ctx, entryOf(KindPath, tpl, a, lift, cleanHits)); err != nil {
			return err
		}
		keep[tpl] = struct{}{}
		res.Entries++
	}
	n, err = m.Store.dropStale(ctx, KindPath, keep)
	res.Dropped += n
	return err
}

func entryOf(kind Kind, value string, a *aggregate, lift float64, clean int64) Entry {
	return Entry{Kind: kind, Value: value, Family: a.family(), DistinctIPs: len(a.ips), Days: len(a.days), Hits: a.hits,
		CleanHits: clean, Lift: lift, FirstSeen: a.first, LastSeen: a.last, Status: StatusCandidate, Origin: OriginLocal, Sample: a.sample}
}

// Run lance un passage et en garde le résultat pour Status.
func (m *Miner) Run(ctx context.Context) (Result, error) {
	m.stateMu.Lock()
	m.running = true
	m.stateMu.Unlock()
	res, err := m.run(ctx)
	m.stateMu.Lock()
	m.running, m.last, m.lastAt, m.lastErr = false, res, m.now(), ""
	if err != nil {
		m.lastErr = err.Error()
	}
	m.stateMu.Unlock()
	return res, err
}

// MinerStatus dit si un passage tourne et ce qu'a fait le dernier.
type MinerStatus struct {
	Running bool      `json:"running"`
	LastAt  time.Time `json:"last_run_at,omitempty"`
	Last    *Result   `json:"last_result,omitempty"`
	Error   string    `json:"last_error,omitempty"`
}

// Status rend l'état du mineur.
func (m *Miner) Status() MinerStatus {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	st := MinerStatus{Running: m.running, LastAt: m.lastAt, Error: m.lastErr}
	if !m.lastAt.IsZero() {
		r := m.last
		st.Last = &r
	}
	return st
}

// Trigger lance un passage en arrière-plan ; faux si un passage tourne déjà.
func (m *Miner) Trigger(ctx context.Context) bool {
	m.stateMu.Lock()
	if m.running {
		m.stateMu.Unlock()
		return false
	}
	m.running = true
	m.stateMu.Unlock()
	go func() {
		defer func() {
			m.stateMu.Lock()
			m.running = false
			m.stateMu.Unlock()
		}()
		m.Run(ctx) //nolint:errcheck
	}()
	return true
}

// Loop lance un passage peu après le démarrage puis un par intervalle, jusqu'à l'annulation de ctx.
func (m *Miner) Loop(ctx context.Context, first, every time.Duration) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Run(ctx) //nolint:errcheck
			t.Reset(every)
		}
	}
}
