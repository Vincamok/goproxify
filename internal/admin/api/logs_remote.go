// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// Recherche dans les logs des passerelles (ADR 0012) : les lignes brutes vivent dans la base de chaque passerelle,
// l'Admin interroge toutes celles qui sont visées et fusionne leurs pages. Activée par `source=edge` sur les routes
// de logs ; sans ce paramètre l'Admin répond depuis sa propre base, comme avant.

const (
	remoteNodeTimeout = 10 * time.Second
	remoteBulkTimeout = 70 * time.Second
	remoteMaxPage     = logapi.MaxLimit
	remoteExportRows  = logapi.MaxBulkLimit
)

// remoteEntry est une ligne de log d'une passerelle dans la réponse de l'API Admin. Les champs suivent logs.Entry ;
// ID est une référence « <passerelle>:<type>:<id> » qui désigne la ligne chez sa passerelle (révélation d'IP).
type remoteEntry struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Ts            string   `json:"ts"`
	Level         string   `json:"level"`
	Component     string   `json:"component"`
	NodeName      string   `json:"node_name"`
	NodeID        string   `json:"node_id"`
	Domain        string   `json:"domain"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Status        int      `json:"status"`
	IP            string   `json:"ip"`
	LatencyMs     int64    `json:"latency_ms"`
	Bytes         int64    `json:"bytes"`
	Message       string   `json:"message"`
	Referrer      string   `json:"referrer,omitempty"`
	RequestID     string   `json:"request_id,omitempty"`
	WAFMatches    []string `json:"waf_matches,omitempty"`
	ThreatSignal  string   `json:"threat_signal,omitempty"`
	TLSJA3        string   `json:"tls_ja3,omitempty"`
	TLSJA4        string   `json:"tls_ja4,omitempty"`
	IPTruncated   bool     `json:"ip_truncated,omitempty"`
	Pseudonymized bool     `json:"pseudonymized,omitempty"`
	Country       string   `json:"country,omitempty"`
}

type unreachableNode struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Error    string `json:"error"`
}

// nodeResult est la réponse d'une passerelle à une recherche, ou son échec.
type nodeResult struct {
	T    edgeproxy.Target
	Resp *logapi.SearchResponse
	Err  error
}

type mergedPage struct {
	Entries     []remoteEntry
	Cursor      string
	HasMore     bool
	Partial     bool
	Unreachable []unreachableNode
}

func remoteRef(nodeID, kind string, id int64) string {
	return nodeID + ":" + kind + ":" + strconv.FormatInt(id, 10)
}

// parseRemoteRef lit la référence d'une ligne ; l'identifiant de passerelle est un UUID, sans « : ».
func parseRemoteRef(ref string) (nodeID, kind string, id int64, err error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 3 {
		return "", "", 0, errors.New("référence de ligne invalide")
	}
	id, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil || id <= 0 || (parts[1] != "access" && parts[1] != "system") {
		return "", "", 0, errors.New("référence de ligne invalide")
	}
	return parts[0], parts[1], id, nil
}

// encodeRemoteCursor et decodeRemoteCursor portent, par passerelle, le jeton de page que celle-ci a rendu.
func encodeRemoteCursor(m map[string]string) string {
	clean := map[string]string{}
	for k, v := range m {
		if v != "" {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return ""
	}
	b, _ := json.Marshal(clean)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeRemoteCursor(c string) (map[string]string, error) {
	if c == "" {
		return map[string]string{}, nil
	}
	if len(c) > 64*1024 {
		return nil, errors.New("jeton de page trop long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mergeSearch fusionne les pages des passerelles, du plus récent au plus ancien, et garde limit lignes. Le jeton
// rendu place chaque passerelle juste après la dernière ligne qu'on en a retenue (et non celle qu'elle a rendue) :
// ce qu'on n'a pas retenu reviendra à la page suivante. Une passerelle injoignable garde sa position.
func mergeSearch(results []nodeResult, prev map[string]string, limit int) mergedPage {
	type item struct {
		e    remoteEntry
		node string
	}
	var all []item
	var out mergedPage
	moreFromNode := false
	for _, r := range results {
		if r.Err != nil {
			out.Unreachable = append(out.Unreachable, unreachableNode{NodeID: r.T.ID, NodeName: r.T.NodeName, Error: r.Err.Error()})
			continue
		}
		if r.Resp.Partial {
			out.Partial = true
		}
		if r.Resp.HasMore {
			moreFromNode = true
		}
		for _, e := range r.Resp.Entries {
			all = append(all, item{node: r.T.ID, e: remoteEntry{
				ID: remoteRef(r.T.ID, e.Kind, e.ID), Kind: e.Kind, Ts: e.Ts, Level: e.Level, Component: e.Component,
				NodeName: r.T.NodeName, NodeID: r.T.ID, Domain: e.Domain, Method: e.Method, Path: e.Path, Status: e.Status,
				IP: e.IP, LatencyMs: e.LatencyMs, Bytes: e.Bytes, Message: e.Message, Referrer: e.Referrer,
				RequestID: e.RequestID, WAFMatches: e.WAFMatches, ThreatSignal: e.ThreatSignal, TLSJA3: e.TLSJA3,
				TLSJA4: e.TLSJA4, IPTruncated: e.IPTruncated, Pseudonymized: e.Pseudonymized,
			}})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].e.Ts != all[j].e.Ts {
			return all[i].e.Ts > all[j].e.Ts
		}
		if all[i].node != all[j].node {
			return all[i].node < all[j].node
		}
		return all[i].e.ID > all[j].e.ID
	})
	if len(all) > limit {
		all = all[:limit]
		out.HasMore = true
	}
	out.HasMore = out.HasMore || moreFromNode
	// Positions par passerelle : celles de la page précédente, avancées jusqu'à la dernière ligne retenue.
	next := map[string]string{}
	positions := map[string]map[string]logapi.Pos{}
	for node, c := range prev {
		next[node] = c
		if pos, err := logapi.DecodeCursor(c); err == nil && pos != nil {
			positions[node] = pos
		}
	}
	for _, it := range all {
		if positions[it.node] == nil {
			positions[it.node] = map[string]logapi.Pos{}
		}
		_, _, id, _ := parseRemoteRef(it.e.ID)
		positions[it.node][it.e.Kind] = logapi.Pos{Ts: it.e.Ts, ID: id}
		out.Entries = append(out.Entries, it.e)
		next[it.node] = logapi.EncodeCursor(positions[it.node])
	}
	if out.Entries == nil {
		out.Entries = []remoteEntry{}
	}
	out.Cursor = encodeRemoteCursor(next)
	return out
}

// remoteParams traduit les filtres de l'API Admin en paramètres de recherche d'une passerelle.
func remoteParams(p logs.SearchParams) logapi.Params {
	return logapi.Params{
		Level: p.Level, Component: p.Component, Domain: p.Domain, IP: p.IP, Method: p.Method, Status: p.Status,
		Path: p.Path, TLSJA3: p.TLSJA3, TLSJA4: p.TLSJA4, Search: p.Search, DateFrom: p.DateFrom, DateTo: p.DateTo,
		Kind: p.Kind, ExcludeInternal: p.ExcludeInternal,
	}
}

func validRemoteDates(p logs.SearchParams) bool {
	for _, d := range []string{p.DateFrom, p.DateTo} {
		if d == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, d); err != nil {
			return false
		}
	}
	return true
}

func (h *LogsHandler) edgeClient(bulk bool) *edgeproxy.Client {
	if bulk {
		if h.BulkEdges == nil {
			h.BulkEdges = edgeproxy.NewBulkClient()
		}
		return h.BulkEdges
	}
	if h.Edges == nil {
		h.Edges = edgeproxy.NewClient()
	}
	return h.Edges
}

// remoteTargets désigne les passerelles visées : toutes, ou celle de node_id / node_name.
func (h *LogsHandler) remoteTargets(ctx context.Context, q url.Values) ([]edgeproxy.Target, error) {
	all, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	id, name := q.Get("node_id"), q.Get("node_name")
	if id == "" && name == "" {
		return all, nil
	}
	var out []edgeproxy.Target
	for _, t := range all {
		if (id != "" && t.ID == id) || (id == "" && name != "" && t.NodeName == name) {
			out = append(out, t)
		}
	}
	return out, nil
}

// fanOut exécute fn pour chaque passerelle en parallèle, chacune avec son propre délai.
func fanOut[T any](ctx context.Context, targets []edgeproxy.Target, timeout time.Duration, fn func(ctx context.Context, t edgeproxy.Target) (T, error)) ([]T, []error) {
	res := make([]T, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			res[i], errs[i] = fn(cctx, t)
		}()
	}
	wg.Wait()
	return res, errs
}

func (h *LogsHandler) searchRemote(ctx context.Context, targets []edgeproxy.Target, base logapi.Params, prev map[string]string, limit int, bulk bool) mergedPage {
	timeout := remoteNodeTimeout
	if bulk {
		timeout = remoteBulkTimeout
	}
	client := h.edgeClient(bulk)
	resp, errs := fanOut(ctx, targets, timeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.SearchResponse, error) {
		p := base
		p.Cursor, p.Limit, p.Bulk = prev[t.ID], limit, bulk
		return client.LogSearch(ctx, t, p)
	})
	results := make([]nodeResult, len(targets))
	for i, t := range targets {
		results[i] = nodeResult{T: t, Resp: resp[i], Err: errs[i]}
	}
	return mergeSearch(results, prev, limit)
}

// countries renseigne le pays de chaque IP d'après le cache GeoIP déjà alimenté (même source que la liste locale).
func (h *LogsHandler) countries(ips map[string]struct{}) map[string]string {
	cc := map[string]string{}
	if h.DB == nil || len(ips) == 0 {
		return cc
	}
	args := make([]any, 0, len(ips))
	placeholders := make([]string, 0, len(ips))
	for ip := range ips {
		placeholders = append(placeholders, "?")
		args = append(args, ip)
	}
	rows, err := h.DB.Query(`SELECT ip, country_code FROM geoip_cache WHERE ip IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return cc
	}
	defer rows.Close()
	for rows.Next() {
		var ip, code string
		if rows.Scan(&ip, &code) == nil && code != "" && code != "XX" {
			cc[ip] = code
		}
	}
	return cc
}

func (h *LogsHandler) attachRemoteCountries(entries []remoteEntry) {
	ips := map[string]struct{}{}
	for _, e := range entries {
		if e.IP != "" {
			ips[e.IP] = struct{}{}
		}
	}
	cc := h.countries(ips)
	for i := range entries {
		entries[i].Country = cc[entries[i].IP]
	}
}

func remotePageSize(q url.Values) int {
	n, _ := strconv.Atoi(q.Get("page_size"))
	switch {
	case n <= 0:
		return logapi.DefaultLimit
	case n > remoteMaxPage:
		return remoteMaxPage
	}
	return n
}

// listRemote : GET /api/v1/logs?source=edge — une page fusionnée des lignes de toutes les passerelles visées.
func (h *LogsHandler) listRemote(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	if !validRemoteDates(p) {
		http.Error(w, "date_from / date_to : RFC3339 requis", http.StatusBadRequest)
		return
	}
	prev, err := decodeRemoteCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Error(w, "cursor invalide", http.StatusBadRequest)
		return
	}
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	limit := remotePageSize(r.URL.Query())
	page := h.searchRemote(r.Context(), targets, remoteParams(p), prev, limit, false)
	h.attachRemoteCountries(page.Entries)
	jsonOK(w, map[string]any{
		"source": "edge", "entries": page.Entries, "has_more": page.HasMore, "cursor": page.Cursor,
		"partial": page.Partial, "unreachable": nonNilUnreachable(page.Unreachable), "page_size": limit,
	})
}

func nonNilUnreachable(u []unreachableNode) []unreachableNode {
	if u == nil {
		return []unreachableNode{}
	}
	return u
}

// histogramRemote additionne les histogrammes des passerelles. Les tranches sont calculées à l'heure locale de
// l'Admin (décalage actuel de son fuseau).
func (h *LogsHandler) histogramRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, bucket string) {
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	_, offset := time.Now().Zone()
	base := remoteParams(p)
	base.Bucket, base.TZOffsetMin = bucket, offset/60
	client := h.edgeClient(false)
	resp, errs := fanOut(r.Context(), targets, remoteNodeTimeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.HistogramResponse, error) {
		return client.LogHistogram(ctx, t, base)
	})
	merged := map[string]*logs.HistPoint{}
	var unreachable []unreachableNode
	partial := false
	for i, t := range targets {
		if errs[i] != nil {
			unreachable = append(unreachable, unreachableNode{NodeID: t.ID, NodeName: t.NodeName, Error: errs[i].Error()})
			continue
		}
		partial = partial || resp[i].Partial
		for _, pt := range resp[i].Points {
			m := merged[pt.Bucket]
			if m == nil {
				m = &logs.HistPoint{Bucket: pt.Bucket}
				merged[pt.Bucket] = m
			}
			m.Total += pt.Total
			m.Warn += pt.Warn
			m.Error += pt.Error
		}
	}
	pts := make([]logs.HistPoint, 0, len(merged))
	for _, m := range merged {
		pts = append(pts, *m)
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].Bucket < pts[j].Bucket })
	jsonOK(w, map[string]any{"source": "edge", "bucket": bucket, "points": pts, "partial": partial, "unreachable": nonNilUnreachable(unreachable)})
}

// facetsRemote additionne les facettes des passerelles ; « node_name » est le nombre de lignes de chacune.
func (h *LogsHandler) facetsRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, fields []string) {
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var forwarded []string
	wantNode := false
	for _, f := range fields {
		if f == "node_name" {
			wantNode = true
		} else {
			forwarded = append(forwarded, f)
		}
	}
	base := remoteParams(p)
	base.Fields = strings.Join(forwarded, ",")
	client := h.edgeClient(false)
	resp, errs := fanOut(r.Context(), targets, remoteNodeTimeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.FacetsResponse, error) {
		return client.LogFacets(ctx, t, base)
	})
	counts := map[string]map[string]int64{}
	var unreachable []unreachableNode
	partial := false
	for i, t := range targets {
		if errs[i] != nil {
			unreachable = append(unreachable, unreachableNode{NodeID: t.ID, NodeName: t.NodeName, Error: errs[i].Error()})
			continue
		}
		partial = partial || resp[i].Partial
		for field, list := range resp[i].Facets {
			if counts[field] == nil {
				counts[field] = map[string]int64{}
			}
			for _, c := range list {
				counts[field][c.Value] += c.Count
			}
		}
		if wantNode && resp[i].Total > 0 {
			if counts["node_name"] == nil {
				counts["node_name"] = map[string]int64{}
			}
			counts["node_name"][t.NodeName] += resp[i].Total
		}
	}
	facets := map[string]any{}
	for field, m := range counts {
		list := make([]logs.FacetCount, 0, len(m))
		for v, c := range m {
			list = append(list, logs.FacetCount{Value: v, Count: c})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count == list[j].Count {
				return list[i].Value < list[j].Value
			}
			return list[i].Count > list[j].Count
		})
		if len(list) > 12 {
			list = list[:12]
		}
		facets[field] = list
	}
	jsonOK(w, map[string]any{"source": "edge", "facets": facets, "partial": partial, "unreachable": nonNilUnreachable(unreachable)})
}

// exportRemote : export des lignes de toutes les passerelles visées (au plus 100 000), au format de l'export local.
func (h *LogsHandler) exportRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, format string) {
	if !validRemoteDates(p) {
		http.Error(w, "date_from / date_to : RFC3339 requis", http.StatusBadRequest)
		return
	}
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	page := h.searchRemote(r.Context(), targets, remoteParams(p), nil, remoteExportRows, true)
	ts := time.Now().Format("20060102-150405")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+".csv")
		if len(page.Unreachable) > 0 {
			w.Header().Set("X-Unreachable-Nodes", strconv.Itoa(len(page.Unreachable)))
		}
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "ts", "level", "component", "node_name", "node_id", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
		for _, e := range page.Entries {
			cw.Write([]string{e.ID, e.Ts, e.Level, e.Component, e.NodeName, e.NodeID, e.Domain, e.Method, e.Path, //nolint:errcheck
				strconv.Itoa(e.Status), e.IP, strconv.FormatInt(e.LatencyMs, 10), strconv.FormatInt(e.Bytes, 10), e.Message})
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+".json")
	if len(page.Unreachable) > 0 {
		w.Header().Set("X-Unreachable-Nodes", strconv.Itoa(len(page.Unreachable)))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(page.Entries) //nolint:errcheck
}

// revealRemote révèle l'IP réelle d'une ligne pseudonymisée chez sa passerelle.
func (h *LogsHandler) revealRemote(ctx context.Context, ref string) (string, error) {
	nodeID, kind, id, err := parseRemoteRef(ref)
	if err != nil {
		return "", err
	}
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.ID != nodeID {
			continue
		}
		resp, err := h.edgeClient(false).LogReveal(ctx, t, logapi.RevealRequest{Kind: kind, ID: id})
		if err != nil {
			return "", err
		}
		return resp.IP, nil
	}
	return "", errors.New("passerelle inconnue")
}

// revealEdgeLine : POST /api/v1/logs/reveal-ip avec entry_ref. Le droit (gdpr:reveal) et le motif sont déjà
// contrôlés par l'appelant ; l'Admin garde sa trace d'audit comme pour une ligne locale, la passerelle la sienne.
func (h *LogsHandler) revealEdgeLine(w http.ResponseWriter, r *http.Request, ref, reason string) {
	if _, _, _, err := parseRemoteRef(ref); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), remoteNodeTimeout)
	defer cancel()
	ip, err := h.revealRemote(ctx, ref)
	var he *edgeproxy.HTTPError
	switch {
	case errors.As(err, &he) && he.Status == http.StatusNotFound:
		logsJSONErr(w, errors.New("ligne introuvable"), http.StatusNotFound)
		return
	case errors.As(err, &he) && he.Status == http.StatusUnprocessableEntity:
		logsJSONErr(w, logs.ErrNotPseudonymized, http.StatusUnprocessableEntity)
		return
	case err != nil:
		logsJSONErr(w, err, http.StatusBadGateway)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "gdpr_reveal_ip", "logs", fmt.Sprintf("entry_ref=%s reason=%q", ref, reason))
	h.Store.Write(logs.Entry{
		Level: "warn", Component: "admin",
		Message: fmt.Sprintf("RGPD révélation IP ligne %s par %s — %s", ref, actor, reason),
	})
	jsonOK(w, map[string]any{
		"entry_ref": ref, "ip": ip, "requested_by": actor, "reason": reason, "ts": time.Now().UTC().Format(time.RFC3339),
	})
}
