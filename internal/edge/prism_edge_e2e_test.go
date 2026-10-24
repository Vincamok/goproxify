// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Prism lit les bases de logs des passerelles (ADR 0012). Ces tests montent trois passerelles réelles et un Admin réel,
// leur font recevoir les mêmes 630 requêtes, et comparent chaque réponse à ce que le jeu d'essai donne quand on le
// calcule à la main : le classement attendu est celui de l'ensemble des lignes, pas d'une somme de tops partiels.

type prismLine struct {
	e    logstore.Entry
	node int
}

// prismFixture : 630 requêtes réparties au hasard sur trois passerelles. Les chemins, les IP, les domaines, les
// composants, les référents et les empreintes ont des comptes tous différents.
func prismFixture(start time.Time) []prismLine {
	rng := rand.New(rand.NewSource(42))
	const n = 630
	// triangle(m) : la valeur j de 0..m-1 apparaît j+1 fois ; la suite est mélangée.
	triangle := func(m int) []int {
		var seq []int
		for j := 0; j < m; j++ {
			for c := 0; c <= j; c++ {
				seq = append(seq, j)
			}
		}
		rng.Shuffle(len(seq), func(a, b int) { seq[a], seq[b] = seq[b], seq[a] })
		return seq
	}
	weighted := func(counts ...int) []int { // counts[j] occurrences de j, mélangées, complétées à n par la dernière valeur
		var seq []int
		for j, c := range counts {
			for i := 0; i < c; i++ {
				seq = append(seq, j)
			}
		}
		for len(seq) < n {
			seq = append(seq, len(counts)-1)
		}
		rng.Shuffle(len(seq), func(a, b int) { seq[a], seq[b] = seq[b], seq[a] })
		return seq[:n]
	}
	paths, ips := triangle(35), triangle(35)
	domains := weighted(100, 200, 330)
	components := weighted(150, 190, 290)
	referrers := weighted(60, 50, 40, 30, 20) // le reste : sans référent
	ja4 := weighted(120, 90, 60, 30)          // le reste : sans empreinte
	statuses := weighted(430, 100, 70, 30)
	var lines []prismLine
	for k := 0; k < n; k++ {
		e := logstore.Entry{
			Ts: start.Add(time.Duration(k) * 30 * time.Second), Level: "info",
			Component: []string{"edge", "waf", "cache"}[components[k]],
			Domain:    []string{"a.example.com", "b.example.com", "c.example.com"}[domains[k]],
			Method:    "GET", Path: fmt.Sprintf("/page/%02d", paths[k]),
			Status: []int{200, 404, 502, 301}[statuses[k]], Bytes: int64(100 + rng.Intn(900)), LatencyMs: int64(1 + rng.Intn(80)),
			IP: fmt.Sprintf("198.51.100.%d", 1+ips[k]),
		}
		if r := referrers[k]; r < 5 && k%7 != 0 {
			e.Referrer = fmt.Sprintf("https://ref%d.example/", r)
		}
		if j := ja4[k]; j < 3 && k%5 != 0 {
			e.TLSJA4, e.TLSJA3 = fmt.Sprintf("t13d%02d", j), fmt.Sprintf("ja3-%d", j)
		}
		if k%11 == 0 {
			e.ThreatSignal = "scan"
		}
		if k%50 == 0 {
			e.IPTruncated = true
		}
		lines = append(lines, prismLine{e: e, node: rng.Intn(3)})
	}
	return lines
}

var prismNodes = []string{"gw-a", "gw-b", "gw-c"}

type prismEnv struct {
	db    *sql.DB
	h     http.Handler
	jwt   string
	gws   []*searchGW
	start time.Time
	end   time.Time
	lines []prismLine
}

func newPrismEnv(t *testing.T) *prismEnv {
	t.Helper()
	start := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Second)
	var gws []*searchGW
	for i, name := range prismNodes {
		gws = append(gws, newSearchGW(t, filepath.Join(t.TempDir(), name), fmt.Sprintf("id-%d", i), name))
	}
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'root@test', 'x', 'superadmin')`); err != nil {
		t.Fatal(err)
	}
	for _, g := range gws {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', ?, ?)`,
			g.id, "tok-"+g.name, g.name, g.srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	ph := &api.PrismHandler{DB: db, Edge: &prismedge.Source{DB: db}}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/prism/", ph)
	jwt, err := auth.SignJWT("u1", "e2e-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	env := &prismEnv{db: db, h: auth.RequireJWT("e2e-secret")(mux), jwt: jwt, gws: gws, start: start, end: start.Add(631 * 30 * time.Second)}
	for _, l := range prismFixture(start) {
		env.write(t, l)
	}
	for _, g := range gws {
		g.logStore.Flush()
	}
	return env
}

// write enregistre une requête dans la passerelle qui la traite et dans les cumuls par minute que celle-ci enverrait.
func (p *prismEnv) write(t *testing.T, l prismLine) {
	t.Helper()
	p.lines = append(p.lines, l)
	p.gws[l.node].logStore.Add(logstore.KindAccess, l.e)
	if _, err := p.db.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests, bytes, latency_ms_sum) VALUES (?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + 1, bytes = bytes + excluded.bytes,
		latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum`,
		logs.MinuteKey(l.e.Ts), prismNodes[l.node], l.e.Domain, l.e.Status, l.e.Bytes, l.e.LatencyMs); err != nil {
		t.Fatal(err)
	}
}

func (p *prismEnv) raw(t *testing.T, path string, q url.Values) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	v := url.Values{}
	for k, vs := range q {
		v[k] = vs
	}
	v.Set("from", p.start.Add(-time.Minute).Format(time.RFC3339))
	v.Set("to", p.end.Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/prism/"+path+"?"+v.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+p.jwt)
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, req)
	return rec, rec.Body.Bytes()
}

func (p *prismEnv) get(t *testing.T, path string, q url.Values) (*httptest.ResponseRecorder, any) {
	t.Helper()
	rec, body := p.raw(t, path, q)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %v : code %d : %s", path, q, rec.Code, rec.Body.String())
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return rec, out
}

// asJSON passe une valeur par JSON : ce que le client recevrait.
func asJSON(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// --- Le jeu d'essai, calculé à la main -------------------------------------------------------------------------------

// pick rend les lignes que les filtres de Prism retiennent.
func (p *prismEnv) pick(f url.Values) []prismLine {
	domains := map[string]bool{}
	for _, d := range strings.Split(f.Get("proxy"), ",") {
		if d != "" {
			domains[d] = true
		}
	}
	var out []prismLine
	for _, l := range p.lines {
		switch {
		case len(domains) > 0 && !domains[l.e.Domain]:
		case f.Get("node_name") != "" && prismNodes[l.node] != f.Get("node_name"):
		case f.Get("ip") != "" && l.e.IP != f.Get("ip"):
		case f.Get("path") != "" && !strings.HasPrefix(l.e.Path, f.Get("path")):
		case f.Get("search") != "" && !strings.Contains(l.e.Path, f.Get("search")):
		default:
			out = append(out, l)
		}
	}
	return out
}

type group struct {
	key                   string
	req, errs, bytes, lat int64
	flagged               int64
	truncated             bool
	ja3                   string
	attributable          map[string]bool
}

// groupBy regroupe les lignes par clé (ok faux : la ligne ne compte pas) et classe par requêtes décroissantes puis clé.
func groupBy(lines []prismLine, key func(logstore.Entry) (string, bool)) []*group {
	by := map[string]*group{}
	for _, l := range lines {
		k, ok := key(l.e)
		if !ok {
			continue
		}
		g := by[k]
		if g == nil {
			g = &group{key: k, attributable: map[string]bool{}}
			by[k] = g
		}
		g.req++
		if l.e.Status >= 400 {
			g.errs++
		}
		g.bytes += l.e.Bytes
		g.lat += l.e.LatencyMs
		if l.e.ThreatSignal != "" || len(l.e.WAFMatches) > 0 {
			g.flagged++
		}
		g.truncated = g.truncated || l.e.IPTruncated
		if l.e.TLSJA3 > g.ja3 {
			g.ja3 = l.e.TLSJA3
		}
		if !l.e.IPTruncated {
			g.attributable[l.e.IP] = true
		}
	}
	out := make([]*group, 0, len(by))
	for _, g := range by {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].req != out[j].req {
			return out[i].req > out[j].req
		}
		return out[i].key < out[j].key
	})
	return out
}

func head[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func distinctIPs(lines []prismLine) int {
	set := map[string]bool{}
	for _, l := range lines {
		set[l.e.IP] = true
	}
	return len(set)
}

func filterSets() map[string]url.Values {
	return map[string]url.Values{
		"sans filtre":       {},
		"un domaine":        {"proxy": {"b.example.com"}},
		"deux domaines":     {"proxy": {"a.example.com,c.example.com"}},
		"préfixe de chemin": {"path": {"/page/1"}},
		"une passerelle":    {"node_name": {"gw-b"}},
		"une IP":            {"ip": {"198.51.100.20"}},
	}
}

func merge(a, b url.Values) url.Values {
	out := url.Values{}
	for _, v := range []url.Values{a, b} {
		for k, vs := range v {
			out[k] = vs
		}
	}
	return out
}

// Chaque classement est celui de l'ensemble des lignes (comptes exacts, égalités départagées par valeur croissante).
func TestPrismRankingsAreThoseOfAllTheRequests(t *testing.T) {
	env := newPrismEnv(t)
	for name, f := range filterSets() {
		lines := env.pick(f)

		// Chemins : page de 10, page décalée, recherche.
		type pathOut = analytics.PathEntry
		paths := func(lines []prismLine, limit, offset int) (got []pathOut, hasMore bool) {
			gs := groupBy(lines, func(e logstore.Entry) (string, bool) { return e.Path, true })
			if offset >= len(gs) {
				return []pathOut{}, false
			}
			gs = gs[offset:]
			hasMore = len(gs) > limit
			for _, g := range head(gs, limit) {
				got = append(got, pathOut{Path: g.key, Requests: g.req, Errors: g.errs, AvgLatMs: float64(g.lat) / float64(g.req), Bytes: g.bytes})
			}
			if got == nil {
				got = []pathOut{}
			}
			return got, hasMore
		}
		for _, c := range []struct {
			q             url.Values
			limit, offset int
		}{{url.Values{"limit": {"10"}}, 10, 0}, {url.Values{"limit": {"7"}, "offset": {"5"}}, 7, 5}, {url.Values{"limit": {"50"}, "search": {"/page/2"}}, 50, 0}} {
			sub := env.pick(merge(f, c.q))
			want, more := paths(sub, c.limit, c.offset)
			_, got := env.get(t, "paths", merge(f, c.q))
			m := got.(map[string]any)
			if !reflect.DeepEqual(m["paths"], asJSON(want)) || m["has_more"] != more {
				t.Errorf("%s chemins %v :\n reçu %v (suite : %v)\n attendu %v (suite : %v)", name, c.q, m["paths"], m["has_more"], asJSON(want), more)
			}
		}

		// IP.
		var ips []analytics.IPEntry
		for _, g := range head(groupBy(lines, func(e logstore.Entry) (string, bool) { return e.IP, true }), 12) {
			ips = append(ips, analytics.IPEntry{IP: g.key, Requests: g.req, Errors: g.errs, Bytes: g.bytes, IPTruncated: g.truncated})
		}
		if ips == nil {
			ips = []analytics.IPEntry{}
		}
		if _, got := env.get(t, "ips", merge(f, url.Values{"limit": {"12"}})); !reflect.DeepEqual(got, asJSON(ips)) {
			t.Errorf("%s IP :\n reçu %v\n attendu %v", name, got, asJSON(ips))
		}

		// Composants (« agents »).
		comps := groupBy(lines, func(e logstore.Entry) (string, bool) { return e.Component, true })
		var total int64
		for _, g := range comps {
			total += g.req
		}
		agents := []analytics.AgentEntry{}
		for _, g := range comps {
			agents = append(agents, analytics.AgentEntry{Name: g.key, Requests: g.req, Pct: float64(g.req) / float64(total) * 100, IsBot: analytics.IsBot(g.key)})
		}
		if len(comps) == 0 {
			agents = []analytics.AgentEntry{}
		}
		if _, got := env.get(t, "agents", merge(f, url.Values{"limit": {"30"}})); !reflect.DeepEqual(got, asJSON(agents)) {
			t.Errorf("%s composants :\n reçu %v\n attendu %v", name, got, asJSON(agents))
		}

		// Référents.
		refs := head(groupBy(lines, func(e logstore.Entry) (string, bool) { return e.Referrer, e.Referrer != "" }), 10)
		total = 0
		for _, g := range refs {
			total += g.req
		}
		wantRefs := []analytics.ReferrerEntry{}
		for _, g := range refs {
			wantRefs = append(wantRefs, analytics.ReferrerEntry{Referrer: g.key, Requests: g.req, Pct: float64(g.req) / float64(total) * 100})
		}
		if _, got := env.get(t, "referrers", merge(f, url.Values{"limit": {"10"}})); !reflect.DeepEqual(got, asJSON(wantRefs)) {
			t.Errorf("%s référents :\n reçu %v\n attendu %v", name, got, asJSON(wantRefs))
		}

		// Empreintes TLS, avec les IP distinctes de chacune.
		wantFP := []analytics.TLSFingerprintEntry{}
		for _, g := range head(groupBy(lines, func(e logstore.Entry) (string, bool) { return e.TLSJA4, e.TLSJA4 != "" }), 10) {
			wantFP = append(wantFP, analytics.TLSFingerprintEntry{JA4: g.key, JA3: g.ja3, Requests: g.req, Errors: g.errs, Flagged: g.flagged, UniqueIPs: int64(len(g.attributable))})
		}
		if _, got := env.get(t, "tls-fingerprints", merge(f, url.Values{"limit": {"10"}})); !reflect.DeepEqual(got, asJSON(wantFP)) {
			t.Errorf("%s empreintes TLS :\n reçu %v\n attendu %v", name, got, asJSON(wantFP))
		}
	}
}

// KPIs, courbe et codes HTTP : les cumuls par minute pour une sélection globale, les passerelles pour une sélection
// filtrée par IP ou chemin. Dans les deux cas, ce que les requêtes donnent.
func TestPrismGlobalAndFilteredFiguresAreThoseOfTheRequests(t *testing.T) {
	env := newPrismEnv(t)
	sets := filterSets()
	sets["chemin et domaines"] = url.Values{"path": {"/page/2"}, "proxy": {"a.example.com,b.example.com"}}
	sets["IP absente"] = url.Values{"ip": {"203.0.113.9"}}
	for name, f := range sets {
		lines := env.pick(f)
		var reqs, errs, byt, lat int64
		counts := map[int]int64{}
		for _, l := range lines {
			reqs++
			byt += l.e.Bytes
			lat += l.e.LatencyMs
			if l.e.Status >= 400 {
				errs++
			}
			counts[l.e.Status]++
		}
		rec, got := env.get(t, "kpis", merge(f, url.Values{"unique_ips": {"1"}}))
		k := got.(map[string]any)
		want := map[string]any{"requests": float64(reqs), "bandwidth": float64(byt), "unique_ips": float64(distinctIPs(lines))}
		if reqs > 0 {
			want["error_rate"] = float64(errs) / float64(reqs) * 100
			want["avg_latency_ms"] = float64(lat) / float64(reqs)
		} else {
			want["error_rate"], want["avg_latency_ms"] = 0.0, 0.0
		}
		for key, w := range want {
			if g, ok := k[key].(float64); !ok || (g-w.(float64) > 1e-9 || w.(float64)-g > 1e-9) {
				t.Errorf("%s : KPI %s = %v, attendu %v", name, key, k[key], w)
			}
		}
		if name != "IP absente" && reqs < 5 {
			t.Fatalf("%s : %d requêtes, le jeu d'essai ne prouve rien", name, reqs)
		}
		if rec.Header().Get("X-Prism-Source") != "edge" {
			t.Errorf("%s : les IP uniques ne viennent pas des passerelles", name)
		}

		for _, bucket := range []struct{ name, layout string }{{"hour", "2006-01-02T15:00"}, {"minute", "2006-01-02T15:04"}, {"day", "2006-01-02"}} {
			agg := map[string]*analytics.TimePoint{}
			for _, l := range lines {
				key := l.e.Ts.Local().Format(bucket.layout)
				tp := agg[key]
				if tp == nil {
					tp = &analytics.TimePoint{Bucket: key}
					agg[key] = tp
				}
				tp.Requests++
				tp.Bytes += l.e.Bytes
				if l.e.Status >= 400 {
					tp.Errors++
				}
			}
			wantTL := []analytics.TimePoint{}
			for _, tp := range agg {
				wantTL = append(wantTL, *tp)
			}
			sort.Slice(wantTL, func(i, j int) bool { return wantTL[i].Bucket < wantTL[j].Bucket })
			if _, got := env.get(t, "timeline", merge(f, url.Values{"bucket": {bucket.name}})); !reflect.DeepEqual(got, asJSON(wantTL)) {
				t.Errorf("%s : courbe par %s :\n reçu %v\n attendu %v", name, bucket.name, got, asJSON(wantTL))
			}
		}
		if _, got := env.get(t, "status", f); !reflect.DeepEqual(got, asJSON(analytics.StatusGroupsFromCounts(counts))) {
			t.Errorf("%s : codes HTTP :\n reçu %v\n attendu %v", name, got, asJSON(analytics.StatusGroupsFromCounts(counts)))
		}
	}
}

func TestPrismUniqueIPsAreExactWhenSmall(t *testing.T) {
	env := newPrismEnv(t)
	for name, f := range filterSets() {
		_, got := env.get(t, "unique-ips", f)
		m := got.(map[string]any)
		if m["unique_ips"] != float64(distinctIPs(env.pick(f))) || m["estimated"] == true {
			t.Errorf("%s : %v IP, attendu %d exactes", name, m, distinctIPs(env.pick(f)))
		}
	}
}

// Une passerelle hors ligne n'empêche pas la réponse : elle est nommée, et le classement est exact sur les autres.
func TestPrismSaysWhichGatewayIsMissing(t *testing.T) {
	env := newPrismEnv(t)
	env.gws[1].srv.Close()
	rec, got := env.get(t, "paths", url.Values{"limit": {"5"}})
	if rec.Header().Get("X-Prism-Unreachable") != "gw-b" {
		t.Fatalf("passerelle manquante = %q", rec.Header().Get("X-Prism-Unreachable"))
	}
	m := got.(map[string]any)
	var remaining []prismLine
	for _, l := range env.lines {
		if l.node != 1 {
			remaining = append(remaining, l)
		}
	}
	want := []analytics.PathEntry{}
	for _, g := range head(groupBy(remaining, func(e logstore.Entry) (string, bool) { return e.Path, true }), 5) {
		want = append(want, analytics.PathEntry{Path: g.key, Requests: g.req, Errors: g.errs, AvgLatMs: float64(g.lat) / float64(g.req), Bytes: g.bytes})
	}
	if m["partial"] != true || !reflect.DeepEqual(m["paths"], asJSON(want)) {
		t.Errorf("réponse = %v, attendu partielle avec %v", m, asJSON(want))
	}
}

// Des passerelles d'avant cette version n'ont pas la route : la réponse est une erreur claire, pas des chiffres faux.
func TestPrismReportsGatewaysThatAreTooOld(t *testing.T) {
	env := newPrismEnv(t)
	for _, g := range env.gws {
		g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	}
	rec, body := env.raw(t, "paths", url.Values{"limit": {"3"}})
	if rec.Code != http.StatusBadGateway || !strings.Contains(string(body), "trop anciennes") {
		t.Errorf("code %d : %s", rec.Code, body)
	}
}

// Sans passerelle enregistrée il n'y a pas de trafic : des listes vides, pas d'erreur.
func TestPrismWithoutGatewaysAnswersWithEmptyLists(t *testing.T) {
	env := newPrismEnv(t)
	if _, err := env.db.Exec(`DELETE FROM tokens`); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []string{"ips", "agents", "referrers", "tls-fingerprints", "geo", "geo/points", "live-ips"} {
		if _, got := env.get(t, ep, url.Values{}); !reflect.DeepEqual(got, []any{}) {
			t.Errorf("%s sans passerelle = %v", ep, got)
		}
	}
	_, got := env.get(t, "paths", url.Values{})
	if m := got.(map[string]any); !reflect.DeepEqual(m["paths"], []any{}) || m["has_more"] != false {
		t.Errorf("chemins sans passerelle = %v", m)
	}
	_, got = env.get(t, "kpis", url.Values{"ip": {"198.51.100.1"}})
	if got.(map[string]any)["requests"] != 0.0 {
		t.Errorf("KPIs filtrés sans passerelle = %v", got)
	}
}

func (p *prismEnv) seedGeo(t *testing.T) {
	t.Helper()
	for j := 1; j <= 35; j++ {
		ip := fmt.Sprintf("198.51.100.%d", j)
		var q string
		switch {
		case j <= 10:
			q = fmt.Sprintf(`INSERT INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES ('%s','FR','France',%f,%f,'Paris','IDF')`, ip, 48.85+float64(j)/1000, 2.35)
		case j <= 20:
			q = fmt.Sprintf(`INSERT INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES ('%s','DE','Germany',%f,%f,'Berlin','BE')`, ip, 52.52, 13.40+float64(j)/100)
		case j <= 25:
			q = fmt.Sprintf(`INSERT INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES ('%s','US','United States',40.7,-74.0,'New York','NY')`, ip)
		case j <= 28:
			q = fmt.Sprintf(`INSERT INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES ('%s','XX','Unknown',0,0,'','')`, ip)
		default:
			continue // pas dans le cache : pays « ? »
		}
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"198.51.100.3", "198.51.100.12", "198.51.100.22", "198.51.100.30"} {
		if _, err := p.db.Exec(`INSERT INTO security_bans (id, ip, source) VALUES (?, ?, 'native')`, "ban-"+ip, ip); err != nil {
			t.Fatal(err)
		}
	}
}

// La répartition par pays et la carte regroupent, avec le cache de géolocalisation de l'Admin, le trafic de chaque IP
// additionné sur les passerelles.
func TestPrismCountryAndCityViewsGroupTheTrafficOfEachIP(t *testing.T) {
	env := newPrismEnv(t)
	env.seedGeo(t)
	for name, f := range map[string]url.Values{"tout": {}, "un domaine": {"proxy": {"a.example.com"}}, "une passerelle": {"node_name": {"gw-c"}}} {
		var counts []analytics.IPCount
		for _, g := range groupBy(env.pick(f), func(e logstore.Entry) (string, bool) { return e.IP, true }) {
			counts = append(counts, analytics.IPCount{IP: g.key, Requests: g.req, Errors: g.errs})
		}
		rec, got := env.get(t, "geo", f)
		if rec.Header().Get("X-Prism-Source") != "edge" {
			t.Fatalf("%s : les pays ne viennent pas des passerelles", name)
		}
		wantGeo := analytics.GeoBreakdownFromIPs(context.Background(), env.db, counts)
		if name == "tout" && len(wantGeo) < 4 {
			t.Fatalf("%d pays seulement : le jeu d'essai ne prouve rien", len(wantGeo))
		}
		if !reflect.DeepEqual(got, asJSON(wantGeo)) {
			t.Errorf("%s : pays\n reçu %v\n attendu %v", name, got, asJSON(wantGeo))
		}
		wantPts := analytics.GeoPointsFromIPs(context.Background(), env.db, counts, 0)
		// Les positions sont des moyennes pondérées : l'ordre des sommes change les derniers chiffres.
		round := func(v any) any {
			for _, p := range v.([]any) {
				m := p.(map[string]any)
				for _, k := range []string{"lat", "lon"} {
					m[k] = math.Round(m[k].(float64)*1e6) / 1e6
				}
			}
			return v
		}
		_, gotPts := env.get(t, "geo/points", f)
		if !reflect.DeepEqual(round(gotPts), round(asJSON(wantPts))) {
			t.Errorf("%s : villes\n reçu %v\n attendu %v", name, gotPts, asJSON(wantPts))
		}
	}
	// Les totaux par pays sont ceux de la table de correspondance du jeu d'essai, écrite à la main.
	byCountry := map[string]int64{}
	for _, l := range env.lines {
		j, _ := strconv.Atoi(strings.TrimPrefix(l.e.IP, "198.51.100."))
		switch {
		case j <= 10:
			byCountry["FR"]++
		case j <= 20:
			byCountry["DE"]++
		case j <= 25:
			byCountry["US"]++
		case j <= 28:
			byCountry["XX"]++
		default:
			byCountry["?"]++
		}
	}
	_, got := env.get(t, "geo", url.Values{})
	for _, e := range got.([]any) {
		m := e.(map[string]any)
		if m["requests"] != float64(byCountry[m["country_code"].(string)]) {
			t.Errorf("pays %v : %v requêtes, attendu %d", m["country_code"], m["requests"], byCountry[m["country_code"].(string)])
		}
	}
}

// Les accès récents de la carte en direct sont les plus récents de l'ensemble des passerelles.
func TestPrismLiveIPsAreTheNewestRequests(t *testing.T) {
	env := newPrismEnv(t)
	env.seedGeo(t)
	q := url.Values{"since": {env.start.Add(-time.Minute).Format(time.RFC3339)}, "limit": {"25"}}
	newest := append([]prismLine(nil), env.lines...)
	sort.Slice(newest, func(i, j int) bool { return newest[i].e.Ts.After(newest[j].e.Ts) })
	var in []analytics.LiveLine
	for _, l := range newest[:25] {
		in = append(in, analytics.LiveLine{IP: l.e.IP, Status: l.e.Status, Domain: l.e.Domain, Ts: l.e.Ts.UTC().Format("2006-01-02T15:04:05.000000Z")})
	}
	want := analytics.LiveEventsFromLines(context.Background(), env.db, in)
	rec, got := env.get(t, "live-ips", q)
	if rec.Header().Get("X-Prism-Source") != "edge" {
		t.Fatal("les accès récents ne viennent pas des passerelles")
	}
	if !reflect.DeepEqual(got, asJSON(want)) {
		t.Errorf("accès récents :\n reçu %v\n attendu %v", got, asJSON(want))
	}
}

// Les exports sont les lignes les plus récentes de la sélection, tous gateways confondus.
func TestPrismExportsAreTheNewestRequests(t *testing.T) {
	env := newPrismEnv(t)
	for name, f := range map[string]url.Values{"tout": {}, "un domaine": {"proxy": {"b.example.com"}}, "une passerelle": {"node_name": {"gw-c"}}} {
		lines := env.pick(f)
		sort.Slice(lines, func(i, j int) bool { return lines[i].e.Ts.After(lines[j].e.Ts) })
		if len(lines) < 100 {
			t.Fatalf("%s : %d lignes, le jeu d'essai ne prouve rien", name, len(lines))
		}
		rec, body := env.raw(t, "export", merge(f, url.Values{"format": {"csv"}}))
		if rec.Header().Get("X-Prism-Source") != "edge" {
			t.Fatalf("%s : l'export ne vient pas des passerelles", name)
		}
		rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
		if err != nil || len(rows) != len(lines)+1 {
			t.Fatalf("%s : %d lignes CSV (%v), attendu %d", name, len(rows)-1, err, len(lines))
		}
		for i, l := range lines {
			r := rows[i+1]
			if r[1] != l.e.Domain || r[2] != "GET" || r[3] != l.e.Path || r[4] != strconv.Itoa(l.e.Status) || r[5] != l.e.IP ||
				r[6] != strconv.FormatInt(l.e.LatencyMs, 10) || r[7] != strconv.FormatInt(l.e.Bytes, 10) {
				t.Fatalf("%s : ligne %d = %v, attendu %+v", name, i, r, l.e)
			}
		}
		_, jbody := env.raw(t, "export", merge(f, url.Values{"format": {"json"}}))
		var jrows []analytics.ExportRow
		if err := json.Unmarshal(jbody, &jrows); err != nil || len(jrows) != len(lines) {
			t.Errorf("%s : %d lignes JSON (%v), attendu %d", name, len(jrows), err, len(lines))
		}
	}
	// Le rapport HTML reprend les totaux et les classements exacts.
	_, html := env.raw(t, "export", url.Values{"format": {"html"}})
	top := head(groupBy(env.lines, func(e logstore.Entry) (string, bool) { return e.Path, true }), 1)[0]
	for _, want := range []string{`<div class="kpi-val">630</div>`, ">" + top.key + "<", fmt.Sprintf("<td>%d</td>", top.req)} {
		if !strings.Contains(string(html), want) {
			t.Errorf("le rapport HTML ne contient pas %q", want)
		}
	}
}

// matching rend les lignes dont l'IP est dans la cible, comme l'aperçu d'un ban les compte.
func (p *prismEnv) matching(target string) (lines []prismLine) {
	bt, err := security.ParseBanTarget(target)
	if err != nil {
		panic(err)
	}
	for _, l := range p.lines {
		if security.TraceMatch(bt.Prefix, l.e.IP) {
			lines = append(lines, l)
		}
	}
	return lines
}

func isBlockedEntry(e logstore.Entry) bool {
	return e.Status == 403 || e.Status == 429 || len(e.WAFMatches) > 0 || e.ThreatSignal != ""
}

func TestBanPreviewCountsTheTrafficOfTheTarget(t *testing.T) {
	env := newPrismEnv(t)
	src := &prismedge.Source{DB: env.db}
	for _, target := range []string{"198.51.100.0/27", "198.51.100.35", "198.51.100.0/24", "203.0.113.0/24"} {
		bt, _ := security.ParseBanTarget(target)
		got, err := api.BanPreview(context.Background(), env.db, src, bt, 24, "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		lines := env.matching(target)
		var nBlocked, nOK int
		hits, okIPs := map[string]int{}, map[string]int{}
		for _, l := range lines {
			hits[l.e.IP]++
			switch {
			case isBlockedEntry(l.e):
				nBlocked++
			case l.e.Status < 400:
				nOK++
				okIPs[l.e.IP]++
			}
		}
		want := map[string]any{"requests": len(lines), "blocked": nBlocked, "ok_requests": nOK, "ips": len(hits), "ok_ips": len(okIPs),
			"top_ips": security.TopCounts(hits, 10), "scan_limited": false}
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("%s : %s = %v, attendu %v", target, k, got[k], w)
			}
		}
		if target == "198.51.100.0/24" && (len(lines) != 630 || nBlocked == 0) {
			t.Errorf("%s : %d requêtes dont %d bloquées, le jeu d'essai ne prouve rien", target, len(lines), nBlocked)
		}
	}
}

func TestIPScanSumsTheActivityOfTheIP(t *testing.T) {
	env := newPrismEnv(t)
	for _, ip := range []string{"198.51.100.35", "198.51.100.7", "198.51.100.77"} {
		_, got := env.get(t, "ip-scan", url.Values{"ip": {ip}})
		m := got.(map[string]any)
		lines := env.pick(url.Values{"ip": {ip}})
		var errs int
		var first, last time.Time
		for _, l := range lines {
			if l.e.Status >= 400 {
				errs++
			}
			if first.IsZero() || l.e.Ts.Before(first) {
				first = l.e.Ts
			}
			if l.e.Ts.After(last) {
				last = l.e.Ts
			}
		}
		if m["requests"] != float64(len(lines)) || m["errors"] != float64(errs) {
			t.Errorf("%s : %v requêtes %v erreurs, attendu %d / %d", ip, m["requests"], m["errors"], len(lines), errs)
		}
		if len(lines) > 0 {
			gf, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(m["first_seen"]))
			gl, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(m["last_seen"]))
			if !gf.Equal(first) || !gl.Equal(last) {
				t.Errorf("%s : de %v à %v, attendu %v à %v", ip, m["first_seen"], m["last_seen"], first, last)
			}
		}
		wantPaths := []any{}
		for _, g := range head(groupBy(lines, func(e logstore.Entry) (string, bool) { return e.Path, true }), 5) {
			wantPaths = append(wantPaths, map[string]any{"path": g.key, "requests": float64(g.req), "errors": float64(g.errs)})
		}
		if !reflect.DeepEqual(m["top_paths"], wantPaths) {
			t.Errorf("%s : chemins %v, attendu %v", ip, m["top_paths"], wantPaths)
		}
	}
}

func TestIPTraceSummarisesTheTrafficOfTheTarget(t *testing.T) {
	env := newPrismEnv(t)
	from, to := env.start.Add(-time.Hour).Format(time.RFC3339), env.end.Add(time.Hour).Format(time.RFC3339)
	for _, tc := range []struct{ name, target, node string }{
		{"une IP", "198.51.100.35", ""}, {"une plage", "198.51.100.0/28", ""}, {"une passerelle", "198.51.100.0/24", "gw-b"}, {"IP absente", "203.0.113.9", ""},
	} {
		get := func(k string) string {
			return map[string]string{"target": tc.target, "from": from, "to": to, "node": tc.node, "limit": "2000"}[k]
		}
		qy, err := api.ParseTraceQuery(get)
		if err != nil {
			t.Fatal(err)
		}
		if err := api.ResolveTraceScope(context.Background(), env.db, nil, &qy); err != nil {
			t.Fatal(err)
		}
		res, err := api.TraceIP(context.Background(), env.db, &prismedge.Source{DB: env.db}, qy)
		if err != nil {
			t.Fatal(err)
		}
		sum := asJSON(res["summary"]).(map[string]any)
		var lines []prismLine
		for _, l := range env.matching(tc.target) {
			if tc.node == "" || prismNodes[l.node] == tc.node {
				lines = append(lines, l)
			}
		}
		var nBlocked int
		statuses := map[string]any{}
		for _, l := range lines {
			if isBlockedEntry(l.e) {
				nBlocked++
			}
			k := strconv.Itoa(l.e.Status/100) + "xx"
			n, _ := statuses[k].(float64)
			statuses[k] = n + 1
		}
		if tc.name != "IP absente" && len(lines) < 20 {
			t.Fatalf("%s : %d requêtes, le jeu d'essai ne prouve rien", tc.name, len(lines))
		}
		if sum["requests"] != float64(len(lines)) || sum["blocked"] != float64(nBlocked) || sum["ip_count"] != float64(distinctIPs(lines)) ||
			!reflect.DeepEqual(sum["statuses"], statuses) {
			t.Errorf("%s : résumé %v\n attendu %d requêtes, %d bloquées, %d IP, codes %v", tc.name, sum, len(lines), nBlocked, distinctIPs(lines), statuses)
		}
	}
}

// addTraffic écrit n requêtes d'une IP dans la passerelle node et dans les cumuls de l'Admin.
func (p *prismEnv) addTraffic(t *testing.T, node int, ip string, n, status int) {
	t.Helper()
	for i := 0; i < n; i++ {
		p.write(t, prismLine{node: node, e: logstore.Entry{Ts: p.start.Add(time.Duration(i) * 40 * time.Second), Level: "info", Component: "edge",
			Domain: "a.example.com", Method: "GET", Path: "/scan", Status: status, Bytes: 10, LatencyMs: 3, IP: ip}})
	}
	p.gws[node].logStore.Flush()
}

func TestAnomaliesAreDetectedFromTheGatewaysAndTheAggregates(t *testing.T) {
	env := newPrismEnv(t)
	env.seedGeo(t)
	// Une IP écrase le trafic (et le met en erreur) depuis un pays qu'elle seule représente.
	env.addTraffic(t, 0, "203.0.113.200", 150, 502)
	env.addTraffic(t, 2, "203.0.113.200", 120, 502)
	if _, err := env.db.Exec(`INSERT INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES ('203.0.113.200','RU','Russia',55.7,37.6,'Moscow','MOW')`); err != nil {
		t.Fatal(err)
	}
	_, got := env.get(t, "anomalies", url.Values{})
	var kinds []string
	for _, a := range got.([]any) {
		m := a.(map[string]any)
		kinds = append(kinds, fmt.Sprint(m["kind"], ":", m["subject"]))
	}
	joined := strings.Join(kinds, " ")
	for _, want := range []string{"dominant_ip:203.0.113.200", "country_errors:RU"} {
		if !strings.Contains(joined, want) {
			t.Errorf("anomalie %q attendue, obtenu %v", want, kinds)
		}
	}
	// Filtré sur cette IP : la sélection se calcule sur les passerelles.
	_, filtered := env.get(t, "anomalies", url.Values{"ip": {"203.0.113.200"}})
	if _, ok := filtered.([]any); !ok {
		t.Errorf("anomalies filtrées = %v", filtered)
	}
}
