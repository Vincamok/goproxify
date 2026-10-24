// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// maxIPRanges borne les intervalles d'IP d'une requête (profondeur d'expression de SQLite).
const maxIPRanges = 400

const (
	logSearchTimeout     = 8 * time.Second
	logBulkSearchTimeout = 60 * time.Second
)

// logSearchGate borne les recherches simultanées : elles lisent la base que le journal d'accès est en train
// d'écrire, et ne doivent pas se disputer le disque avec le trafic. Une page normale à deux, un export à un seul.
type logSearchGate struct {
	normal chan struct{}
	bulk   chan struct{}
}

func newLogSearchGate() *logSearchGate {
	return &logSearchGate{normal: make(chan struct{}, 2), bulk: make(chan struct{}, 1)}
}

// acquire rend la fonction de libération, ou false si la passerelle est déjà occupée.
func (g *logSearchGate) acquire(bulk bool) (func(), bool) {
	ch := g.normal
	if bulk {
		ch = g.bulk
	}
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return nil, false
	}
}

func (s *Server) searchGate() *logSearchGate {
	s.logGateOnce.Do(func() { s.logGate = newLogSearchGate() })
	return s.logGate
}

func encodeLogCursor(next map[logstore.Kind]logstore.Position) string {
	m := map[string]logapi.Pos{}
	for k, p := range next {
		m[string(k)] = logapi.Pos{Ts: p.Ts, ID: p.ID}
	}
	return logapi.EncodeCursor(m)
}

func decodeLogCursor(c string) (map[logstore.Kind]logstore.Position, error) {
	m, err := logapi.DecodeCursor(c)
	if err != nil || m == nil {
		return nil, err
	}
	out := map[logstore.Kind]logstore.Position{}
	for k, p := range m {
		out[logstore.Kind(k)] = logstore.Position{Ts: p.Ts, ID: p.ID}
	}
	return out, nil
}

// logQuery traduit les paramètres de l'API en requête sur la base.
func logQuery(p logapi.Params) (logstore.Query, error) {
	q := logstore.Query{
		Level: p.Level, Component: p.Component, Domain: p.Domain, IP: p.IP, Method: p.Method, Status: p.Status,
		Path: p.Path, TLSJA3: p.TLSJA3, TLSJA4: p.TLSJA4, Search: p.Search, RequestID: p.RequestID, ExcludeInternal: p.ExcludeInternal,
		PathPrefix: p.PathPrefix, IPFrom: p.IPFrom, IPTo: p.IPTo, AttributableOnly: p.Attributable,
	}
	for _, r := range strings.Split(p.IPRanges, ",") {
		if lo, hi, ok := strings.Cut(r, "|"); ok && lo != "" && hi != "" && len(q.IPRanges) < maxIPRanges {
			q.IPRanges = append(q.IPRanges, [2]string{lo, hi})
		}
	}
	for _, d := range strings.Split(p.Domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			q.Domains = append(q.Domains, d)
		}
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		q.Kinds = []logstore.Kind{logstore.KindAccess}
	case "system":
		q.Kinds = []logstore.Kind{logstore.KindSystem}
	case "":
	default:
		return q, errors.New("kind inconnu")
	}
	var err error
	if p.DateFrom != "" {
		if q.From, err = time.Parse(time.RFC3339, p.DateFrom); err != nil {
			return q, errors.New("date_from illisible")
		}
	}
	if p.DateTo != "" {
		if q.To, err = time.Parse(time.RFC3339, p.DateTo); err != nil {
			return q, errors.New("date_to illisible")
		}
	}
	return q, nil
}

// withLogGate applique le plafond de recherches simultanées et le délai de la requête.
func (s *Server) withLogGate(w http.ResponseWriter, r *http.Request, bulk bool, fn func(ctx context.Context)) {
	timeout := logSearchTimeout
	if bulk {
		timeout = logBulkSearchTimeout
	}
	s.withLogGateFor(w, r, bulk, timeout, fn)
}

func (s *Server) withLogGateFor(w http.ResponseWriter, r *http.Request, bulk bool, timeout time.Duration, fn func(ctx context.Context)) {
	if s.logStore == nil {
		http.Error(w, "base de logs indisponible", http.StatusServiceUnavailable)
		return
	}
	release, ok := s.searchGate().acquire(bulk)
	if !ok {
		w.Header().Set("Retry-After", "2")
		http.Error(w, "passerelle occupée à chercher dans ses logs, réessayer", http.StatusTooManyRequests)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	fn(ctx)
}

func (s *Server) logEntry(row logstore.Row, kind logstore.Kind) logapi.Entry {
	se := edgelog.ShipEntryFromRow(row, kind, s.cfg.Identity.NodeName)
	return logapi.Entry{
		ID: row.ID, Kind: string(kind), Ts: row.Ts.UTC().Format(logapi.TsLayout), Level: se.Level, Component: se.Component, Domain: se.Domain,
		Method: se.Method, Path: se.Path, Status: se.Status, IP: se.IP, LatencyMs: se.LatencyMs, Bytes: se.Bytes,
		Message: se.Message, Referrer: se.Referrer, RequestID: se.RequestID, WAFMatches: se.WAFMatches,
		ThreatSignal: se.ThreatSignal, TLSJA3: se.TLSJA3, TLSJA4: se.TLSJA4, IPTruncated: se.IPTruncated,
		Pseudonymized: row.Pseudonymized,
	}
}

// handleLogSearch : GET /internal/v1/logs/search — une page de lignes, du plus récent au plus ancien.
func (s *Server) handleLogSearch(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := logQuery(p)
	if err == nil {
		q.After, err = decodeLogCursor(p.Cursor)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch {
	case p.Limit <= 0:
		q.Limit = logapi.DefaultLimit
	case p.Bulk:
		q.Limit = min(p.Limit, logapi.MaxBulkLimit)
	default:
		q.Limit = min(p.Limit, logapi.MaxLimit)
	}
	s.withLogGate(w, r, p.Bulk, func(ctx context.Context) {
		page, err := s.logStore.Search(ctx, q)
		if err != nil {
			s.log.Warn("logs: recherche échouée", "err", err)
			http.Error(w, "recherche impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.SearchResponse{Entries: make([]logapi.Entry, 0, len(page.Rows)), HasMore: page.HasMore, Partial: page.Partial}
		for _, row := range page.Rows {
			out.Entries = append(out.Entries, s.logEntry(row, row.Kind()))
		}
		out.Next = encodeLogCursor(page.Next)
		writeJSON(w, out)
	})
}

// handleLogHistogram : GET /internal/v1/logs/histogram.
func (s *Server) handleLogHistogram(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := logQuery(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bucket := p.Bucket
	if bucket != "minute" && bucket != "day" {
		bucket = "hour"
	}
	s.withLogGate(w, r, false, func(ctx context.Context) {
		pts, partial, err := s.logStore.Histogram(ctx, q, bucket, p.TZOffsetMin)
		if err != nil {
			s.log.Warn("logs: histogramme échoué", "err", err)
			http.Error(w, "histogramme impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.HistogramResponse{Points: make([]logapi.HistPoint, len(pts)), Partial: partial}
		for i, h := range pts {
			out.Points[i] = logapi.HistPoint{Bucket: h.Bucket, Total: h.Total, Warn: h.Warn, Error: h.Error}
		}
		writeJSON(w, out)
	})
}

// handleLogFacets : GET /internal/v1/logs/facets.
func (s *Server) handleLogFacets(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := logQuery(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fields := []string{"level", "component", "domain", "method"}
	if p.Fields != "" {
		fields = strings.Split(p.Fields, ",")
	}
	s.withLogGate(w, r, false, func(ctx context.Context) {
		facets, total, partial, err := s.logStore.Facets(ctx, q, fields)
		if err != nil {
			s.log.Warn("logs: facettes échouées", "err", err)
			http.Error(w, "facettes impossibles", http.StatusInternalServerError)
			return
		}
		out := logapi.FacetsResponse{Total: total, Partial: partial, Facets: map[string][]logapi.FacetCount{}}
		for field, list := range facets {
			for _, c := range list {
				out.Facets[field] = append(out.Facets[field], logapi.FacetCount{Value: c.Value, Count: c.Count})
			}
		}
		writeJSON(w, out)
	})
}

// handleLogReveal : POST /internal/v1/logs/reveal — l'IP réelle d'une ligne pseudonymisée. La demande vient de
// l'Admin, qui a déjà contrôlé le droit de l'utilisateur et le motif ; la passerelle garde sa propre trace.
func (s *Server) handleLogReveal(w http.ResponseWriter, r *http.Request) {
	if s.logStore == nil {
		http.Error(w, "base de logs indisponible", http.StatusServiceUnavailable)
		return
	}
	var req logapi.RevealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	kind := logstore.Kind(req.Kind)
	if kind != logstore.KindAccess && kind != logstore.KindSystem {
		http.Error(w, "kind inconnu", http.StatusBadRequest)
		return
	}
	ip, err := s.logStore.RevealIP(kind, req.ID)
	switch {
	case errors.Is(err, logstore.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, logstore.ErrNotPseudonymized):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, logstore.ErrNoKey):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		s.log.Warn("logs: révélation d'IP échouée", "err", err)
		http.Error(w, "révélation impossible", http.StatusInternalServerError)
	default:
		s.log.Warn("rgpd: IP réelle révélée sur demande de l'Admin", "kind", req.Kind, "id", req.ID)
		writeJSON(w, logapi.RevealResponse{IP: ip})
	}
}

// eraseIP supprime d'une IP les lignes de la base de logs (accès et système, pseudonymisées comprises) et l'historique
// des bans de la passerelle ; il rend les comptes.
func (s *Server) eraseIP(ip string) (lines, bans int64, err error) {
	if s.threatEngine != nil {
		s.threatEngine.ForgetIP(ip)
	}
	if s.logStore != nil {
		if lines, err = s.logStore.EraseIP(ip); err != nil {
			return lines, 0, err
		}
	}
	if s.bansDB != nil {
		if bans, err = s.bansDB.EraseIP(ip, ipcrypt.CanonicalIP(ip)); err != nil {
			return lines, bans, err
		}
	}
	return lines, bans, nil
}

// handleLogErase : POST /internal/v1/logs/erase — efface une IP (droit à l'effacement RGPD) et rend ce qui a été
// supprimé, pour que l'Admin puisse dire, passerelle par passerelle, que l'effacement a eu lieu. L'IP doit être une
// adresse : une valeur quelconque (« [pseudonymisé] ») ne doit jamais effacer d'un coup toutes les lignes pseudonymisées.
func (s *Server) handleLogErase(w http.ResponseWriter, r *http.Request) {
	var req logapi.EraseRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	if _, err := netip.ParseAddr(req.IP); err != nil {
		http.Error(w, "adresse IP invalide", http.StatusBadRequest)
		return
	}
	lines, bans, err := s.eraseIP(req.IP)
	s.persistEphorState()
	if err != nil {
		s.log.Warn("rgpd: effacement d'une IP échoué", "err", err)
		http.Error(w, "effacement impossible", http.StatusInternalServerError)
		return
	}
	s.log.Info("rgpd: IP effacée de la passerelle sur demande de l'Admin", "log_lines", lines, "ban_rows", bans)
	writeJSON(w, logapi.EraseResponse{LogLines: lines, BanRows: bans})
}
