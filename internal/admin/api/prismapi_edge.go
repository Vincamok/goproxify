// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// Les classements, les IP uniques, la carte, les exports et toute sélection filtrée par IP ou par chemin portent sur des
// lignes d'accès : elles vivent dans la base de logs de chaque passerelle (ADR 0012), que l'Admin interroge et fusionne.
// Sans passerelle enregistrée il n'y a pas de trafic : les listes sont vides.

// source désigne les passerelles à interroger pour cette sélection, ou nil quand il n'y en a aucune.
func (h *PrismHandler) source(r *http.Request, p analytics.Params) *prismedge.Source {
	if h.Edge == nil || !h.Edge.Available(r.Context(), p) {
		return nil
	}
	return h.Edge
}

// edgeFailed répond à l'échec d'un calcul sur les passerelles.
func edgeFailed(w http.ResponseWriter, err error) {
	prismJSONErr(w, err, http.StatusBadGateway)
}

// kpisFor calcule les KPIs : les cumuls par minute pour une sélection globale, les passerelles pour une sélection
// filtrée par IP ou par chemin et pour les IP uniques.
func (h *PrismHandler) kpisFor(r *http.Request, p analytics.Params, includeUnique bool) (analytics.KPIs, prismedge.Meta, error) {
	e := h.source(r, p)
	if prismedge.Filtered(p) {
		if e == nil {
			return analytics.KPIs{}, prismedge.Meta{}, nil
		}
		return e.FilteredKPIs(r.Context(), p, includeUnique)
	}
	kpis := analytics.GetKPIs(h.DB, p)
	if !includeUnique || e == nil {
		return kpis, prismedge.Meta{}, nil
	}
	n, meta, err := e.UniqueIPs(r.Context(), p)
	if err != nil {
		return kpis, meta, err
	}
	kpis.UniqueIPs = n
	return kpis, meta, nil
}

func (h *PrismHandler) kpis(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	kpis, meta, err := h.kpisFor(r, p, r.URL.Query().Get("unique_ips") == "1")
	if err != nil {
		edgeFailed(w, err)
		return
	}
	if meta.Nodes > 0 {
		meta.Header(w.Header())
	}
	jsonOK(w, kpis)
}

func (h *PrismHandler) uniqueIPs(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	e := h.source(r, p)
	if e == nil {
		jsonOK(w, map[string]any{"unique_ips": 0, "estimated": false, "partial": false, "unreachable": []prismedge.Unreachable{}})
		return
	}
	n, meta, err := e.UniqueIPs(r.Context(), p)
	if err != nil {
		edgeFailed(w, err)
		return
	}
	meta.Header(w.Header())
	jsonOK(w, map[string]any{"unique_ips": n, "estimated": meta.Estimated, "partial": meta.Degraded(), "unreachable": meta.Unreachable})
}

func (h *PrismHandler) timeline(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "hour"
	}
	if prismedge.Filtered(p) {
		e := h.source(r, p)
		if e == nil {
			jsonOK(w, []analytics.TimePoint{})
			return
		}
		series, meta, err := e.MinuteSeries(r.Context(), p)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		jsonOK(w, analytics.TimelineFromMinutes(series, bucket))
		return
	}
	pts := analytics.GetTimeline(h.DB, p, bucket)
	if pts == nil {
		pts = []analytics.TimePoint{}
	}
	jsonOK(w, pts)
}

func (h *PrismHandler) status(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	if prismedge.Filtered(p) {
		e := h.source(r, p)
		if e == nil {
			jsonOK(w, analytics.StatusGroupsFromCounts(nil))
			return
		}
		counts, meta, err := e.StatusCounts(r.Context(), p)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		jsonOK(w, analytics.StatusGroupsFromCounts(counts))
		return
	}
	jsonOK(w, analytics.GetStatusGroups(h.DB, p))
}

func (h *PrismHandler) paths(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	out := map[string]any{"paths": []analytics.PathEntry{}, "has_more": false, "limit": limit, "offset": offset, "partial": false, "unreachable": []prismedge.Unreachable{}}
	if e := h.source(r, p); e != nil {
		paths, hasMore, meta, err := e.TopPaths(r.Context(), p, q.Get("search"), limit, offset)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		out["paths"], out["has_more"], out["partial"], out["unreachable"] = paths, hasMore, meta.Degraded(), meta.Unreachable
	}
	jsonOK(w, out)
}

func (h *PrismHandler) ips(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ips := []analytics.IPEntry{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.TopIPs(r.Context(), p, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		ips = got
	}
	jsonOK(w, ips)
}

func (h *PrismHandler) agents(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	agents := []analytics.AgentEntry{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.TopComponents(r.Context(), p, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		agents = got
	}
	jsonOK(w, agents)
}

func (h *PrismHandler) referrers(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	refs := []analytics.ReferrerEntry{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.TopReferrers(r.Context(), p, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		refs = got
	}
	jsonOK(w, refs)
}

func (h *PrismHandler) tlsFingerprints(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	fps := []analytics.TLSFingerprintEntry{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.TopTLSFingerprints(r.Context(), p, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		fps = got
	}
	jsonOK(w, fps)
}

func (h *PrismHandler) geo(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	entries := []analytics.GeoEntry{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.GeoBreakdown(r.Context(), p)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		if got != nil {
			entries = got
		}
	}
	jsonOK(w, entries)
}

func (h *PrismHandler) geoPoints(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	points := []analytics.GeoPoint{}
	if e := h.source(r, p); e != nil {
		got, meta, err := e.GeoPoints(r.Context(), p, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		if got != nil {
			points = got
		}
	}
	jsonOK(w, points)
}

func (h *PrismHandler) liveIPs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := time.Now().Add(-10 * time.Second)
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			since = t
		}
	}
	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	events := []analytics.LiveIPEvent{}
	lp := analytics.Params{Proxy: q.Get("proxy"), NodeName: q.Get("node_name")}
	if e := h.source(r, lp); e != nil {
		got, meta, err := e.LiveIPs(r.Context(), since, lp.Proxy, lp.NodeName, limit)
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta.Header(w.Header())
		if got != nil {
			events = got
		}
	}
	jsonOK(w, events)
}

// export rend les lignes d'accès les plus récentes de la sélection (CSV, JSON) ou le rapport HTML.
func (h *PrismHandler) export(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	format := r.URL.Query().Get("format")
	if format != "json" && format != "html" {
		format = "csv"
	}
	ts := time.Now().Format("20060102-150405")
	e := h.source(r, p)
	var meta prismedge.Meta
	switch format {
	case "html":
		var paths []analytics.PathEntry
		var ips []analytics.IPEntry
		kpis, m, err := h.kpisFor(r, p, true)
		if err == nil && e != nil {
			if paths, _, _, err = e.TopPaths(r.Context(), p, "", 20, 0); err == nil {
				ips, _, err = e.TopIPs(r.Context(), p, 20)
			}
		}
		if err != nil {
			edgeFailed(w, err)
			return
		}
		meta = m
		var timeline []analytics.TimePoint
		var groups []analytics.StatusGroup
		if !prismedge.Filtered(p) {
			timeline, groups = analytics.GetTimeline(h.DB, p, "hour"), analytics.GetStatusGroups(h.DB, p)
		}
		meta.Header(w.Header())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=prism-report-"+ts+".html")
		w.Write(analytics.HTMLReport(p, kpis, timeline, groups, paths, ips)) //nolint:errcheck
	default:
		rows := []analytics.ExportRow{}
		if e != nil {
			got, m, err := e.ExportRows(r.Context(), p)
			if err != nil {
				edgeFailed(w, err)
				return
			}
			rows, meta = got, m
		}
		meta.Header(w.Header())
		if format == "json" {
			data, err := analytics.JSONFromRows(rows)
			if err != nil {
				prismJSONErr(w, err, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=prism-export-"+ts+".json")
			w.Write(data) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=prism-export-"+ts+".csv")
		w.Write(analytics.CSVFromRows(rows)) //nolint:errcheck
	}
}

// anomalySource : les passerelles pour les règles d'anomalies qui portent sur des lignes, ou nil sans passerelle.
func (h *PrismHandler) anomalySource() analytics.Remote {
	if h.Edge == nil {
		return nil
	}
	return prismedge.Anomalies{S: h.Edge}
}
