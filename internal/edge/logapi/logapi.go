// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logapi décrit le contrat HTTP entre l'Admin et la base de logs d'une passerelle (ADR 0012) : paramètres
// de recherche, entrées, facettes, histogramme. La passerelle répond, l'Admin interroge chaque passerelle et fusionne.
package logapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
)

// Chemins de l'API interne de la passerelle.
const (
	PathSearch    = "/internal/v1/logs/search"
	PathHistogram = "/internal/v1/logs/histogram"
	PathFacets    = "/internal/v1/logs/facets"
	PathReveal    = "/internal/v1/logs/reveal"
)

// Plafonds d'une recherche : une page normale tient dans 500 lignes ; un export en réclame jusqu'à 100 000.
const (
	DefaultLimit = 50
	MaxLimit     = 500
	MaxBulkLimit = 100000
)

// Params sont les filtres d'une recherche, les mêmes que ceux de GET /api/v1/logs de l'Admin.
type Params struct {
	Level, Component, Domain, IP, Method, Status, Path string
	TLSJA3, TLSJA4, Search                             string
	// DateFrom et DateTo : bornes RFC3339.
	DateFrom, DateTo string
	// Kind : "access", "system" ou vide (les deux).
	Kind            string
	ExcludeInternal bool
	// Cursor est le jeton Next de la page précédente ; vide pour la première page.
	Cursor string
	Limit  int
	// Bulk autorise une page jusqu'à MaxBulkLimit (export) : un seul à la fois, avec un délai plus long.
	Bulk bool
	// TZOffsetMin décale les tranches de l'histogramme (minutes à l'est de UTC) ; Bucket : minute, hour ou day.
	TZOffsetMin int
	Bucket      string
	// Fields : facettes demandées (virgules), pour /facets.
	Fields string
}

// Values encode les paramètres dans une requête.
func (p Params) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("level", p.Level)
	set("component", p.Component)
	set("domain", p.Domain)
	set("ip", p.IP)
	set("method", p.Method)
	set("status", p.Status)
	set("path", p.Path)
	set("tls_ja3", p.TLSJA3)
	set("tls_ja4", p.TLSJA4)
	set("search", p.Search)
	set("date_from", p.DateFrom)
	set("date_to", p.DateTo)
	set("kind", p.Kind)
	set("cursor", p.Cursor)
	set("bucket", p.Bucket)
	set("fields", p.Fields)
	if p.ExcludeInternal {
		v.Set("exclude_internal", "1")
	}
	if p.Bulk {
		v.Set("bulk", "1")
	}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.TZOffsetMin != 0 {
		v.Set("tz_offset_min", strconv.Itoa(p.TZOffsetMin))
	}
	return v
}

// ParamsFromValues décode les paramètres d'une requête.
func ParamsFromValues(v url.Values) Params {
	limit, _ := strconv.Atoi(v.Get("limit"))
	tz, _ := strconv.Atoi(v.Get("tz_offset_min"))
	return Params{
		Level: v.Get("level"), Component: v.Get("component"), Domain: v.Get("domain"), IP: v.Get("ip"),
		Method: v.Get("method"), Status: v.Get("status"), Path: v.Get("path"), TLSJA3: v.Get("tls_ja3"),
		TLSJA4: v.Get("tls_ja4"), Search: v.Get("search"), DateFrom: v.Get("date_from"), DateTo: v.Get("date_to"),
		Kind: v.Get("kind"), ExcludeInternal: v.Get("exclude_internal") == "1" || v.Get("exclude_internal") == "true",
		Cursor: v.Get("cursor"), Limit: limit, Bulk: v.Get("bulk") == "1", TZOffsetMin: tz, Bucket: v.Get("bucket"),
		Fields: v.Get("fields"),
	}
}

// Entry est une ligne de log. Les champs suivent logs.Entry de l'Admin ; ID est l'identifiant global dans la base de
// la passerelle (période << 40 | rowid), unique pour un type (Kind) de cette passerelle.
type Entry struct {
	ID            int64    `json:"id"`
	Kind          string   `json:"kind"`
	Ts            string   `json:"ts"` // RFC3339Nano, UTC
	Level         string   `json:"level"`
	Component     string   `json:"component"`
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
}

// SearchResponse est une page de résultats, du plus récent au plus ancien. Next est le jeton de la page suivante.
// Partial : le délai de la recherche est écoulé avant qu'elle ait parcouru toute la période (affiner le filtre).
type SearchResponse struct {
	Entries []Entry `json:"entries"`
	Next    string  `json:"next"`
	HasMore bool    `json:"has_more"`
	Partial bool    `json:"partial"`
}

// FacetCount : une valeur d'un champ et son nombre d'entrées.
type FacetCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FacetsResponse : les valeurs les plus fréquentes de chaque champ demandé, et le nombre total d'entrées filtrées.
type FacetsResponse struct {
	Total   int64                   `json:"total"`
	Facets  map[string][]FacetCount `json:"facets"`
	Partial bool                    `json:"partial"`
}

// HistPoint compte les entrées d'une tranche de temps, par niveau.
type HistPoint struct {
	Bucket string `json:"bucket"`
	Total  int64  `json:"total"`
	Warn   int64  `json:"warn"`
	Error  int64  `json:"error"`
}

// HistogramResponse : les tranches, dans l'ordre chronologique.
type HistogramResponse struct {
	Points  []HistPoint `json:"points"`
	Partial bool        `json:"partial"`
}

// RevealRequest demande l'IP réelle d'une ligne pseudonymisée.
type RevealRequest struct {
	Kind string `json:"kind"`
	ID   int64  `json:"id"`
}

// RevealResponse porte l'IP réelle.
type RevealResponse struct {
	IP string `json:"ip"`
}

// TsLayout est le format des horodatages d'une Entry : largeur fixe, donc comparables en texte et utilisables tels
// quels dans un curseur. C'est aussi du RFC3339 valide.
const TsLayout = "2006-01-02T15:04:05.000000Z"

// Pos est la position d'une ligne dans un type de log de la passerelle : celle de la dernière ligne rendue.
type Pos struct {
	Ts string `json:"ts"`
	ID int64  `json:"id"`
}

// MaxCursorBytes borne un jeton de page reçu.
const MaxCursorBytes = 1024

// EncodeCursor fabrique le jeton d'une page à partir des positions par type ("access", "system").
func EncodeCursor(pos map[string]Pos) string {
	m := map[string]Pos{}
	for k, p := range pos {
		if p.Ts != "" {
			m[k] = p
		}
	}
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor lit un jeton de page ; un jeton vide est la première page.
func DecodeCursor(c string) (map[string]Pos, error) {
	if c == "" {
		return nil, nil
	}
	if len(c) > MaxCursorBytes {
		return nil, errors.New("jeton de page trop long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, err
	}
	var m map[string]Pos
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k := range m {
		if k != "access" && k != "system" {
			return nil, errors.New("jeton de page inconnu")
		}
	}
	return m, nil
}
