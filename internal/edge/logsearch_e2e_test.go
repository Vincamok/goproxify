// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// Passerelles réelles (base de logs, routes de recherche, jeton exigé) et Admin réel (base, route /api/v1/logs) :
// la recherche fusionnée est vérifiée de bout en bout, sans simulacre du transport.

type searchGW struct {
	*Server
	srv  *httptest.Server
	id   string
	name string
}

func newSearchGW(t *testing.T, dir, id, name string) *searchGW {
	t.Helper()
	s := newLogGateway(t, dir, "cle-"+name)
	s.cfg.Identity.NodeName = name
	mux := http.NewServeMux()
	s.registerLogRoutes(mux)
	token := "tok-" + name
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "401", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return &searchGW{Server: s, srv: srv, id: id, name: name}
}

// add écrit n accès à partir de start, un par seconde, sur le chemin /<name>/<i>.
func (g *searchGW) add(start time.Time, n int, mutate func(i int, e *logstore.Entry)) {
	for i := 0; i < n; i++ {
		e := logstore.Entry{
			Ts: start.Add(time.Duration(i) * time.Second), Level: "info", Component: "edge", Domain: "app.example.com",
			Method: "GET", Path: fmt.Sprintf("/%s/%d", g.name, i), Status: 200, Bytes: 10, LatencyMs: 5, IP: "198.51.100.1",
			UserAgent: "curl/8",
		}
		if mutate != nil {
			mutate(i, &e)
		}
		g.logStore.Add(logstore.KindAccess, e)
	}
	g.logStore.Flush()
}

type searchAdmin struct {
	db    *sql.DB
	h     http.Handler
	jwt   string
	quiet *slog.Logger
}

func newSearchAdmin(t *testing.T, gws ...*searchGW) *searchAdmin {
	t.Helper()
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
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	lh := &api.LogsHandler{Log: quiet, Store: logs.New(db), DB: db}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/logs", lh)
	mux.Handle("/api/v1/logs/", lh)
	jwt, err := auth.SignJWT("u1", "e2e-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &searchAdmin{db: db, h: auth.RequireJWT("e2e-secret")(mux), jwt: jwt, quiet: quiet}
}

func (a *searchAdmin) do(method, path string, q url.Values, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	u := path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req := httptest.NewRequest(method, u, &buf)
	req.Header.Set("Authorization", "Bearer "+a.jwt)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

type listResp struct {
	Source      string `json:"source"`
	HasMore     bool   `json:"has_more"`
	Cursor      string `json:"cursor"`
	Partial     bool   `json:"partial"`
	Unreachable []struct {
		NodeID   string `json:"node_id"`
		NodeName string `json:"node_name"`
		Error    string `json:"error"`
	} `json:"unreachable"`
	Entries []struct {
		ID            string `json:"id"`
		Ts            string `json:"ts"`
		Path          string `json:"path"`
		NodeName      string `json:"node_name"`
		NodeID        string `json:"node_id"`
		IP            string `json:"ip"`
		Pseudonymized bool   `json:"pseudonymized"`
	} `json:"entries"`
}

func (a *searchAdmin) list(t *testing.T, q url.Values) listResp {
	t.Helper()
	q.Set("source", "edge")
	rec := a.do(http.MethodGet, "/api/v1/logs", q, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("liste : code %d : %s", rec.Code, rec.Body.String())
	}
	var out listResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

const idA, idB = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"

func twoGateways(t *testing.T) (*searchGW, *searchGW, *searchAdmin) {
	t.Helper()
	dir := t.TempDir()
	a := newSearchGW(t, filepath.Join(dir, "a"), idA, "gw-a")
	b := newSearchGW(t, filepath.Join(dir, "b"), idB, "gw-b")
	base := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	a.add(base, 20, nil)                     // 10:00:00 → 10:00:19
	b.add(base.Add(10*time.Second), 20, nil) // 10:00:10 → 10:00:29, chevauche
	return a, b, newSearchAdmin(t, a, b)
}

// Toutes les pages d'une recherche fusionnée : chaque ligne des deux passerelles une fois, du plus récent au plus ancien.
func TestMergedSearchPagesThroughTwoGateways(t *testing.T) {
	_, _, admin := twoGateways(t)
	seen := map[string]bool{}
	var tsList []string
	cursor := ""
	for pages := 0; pages < 20; pages++ {
		q := url.Values{"page_size": {"7"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		p := admin.list(t, q)
		if p.Source != "edge" || len(p.Unreachable) != 0 {
			t.Fatalf("source=%q injoignables=%v", p.Source, p.Unreachable)
		}
		for _, e := range p.Entries {
			key := e.NodeName + e.Path
			if seen[key] {
				t.Fatalf("ligne en double : %s", key)
			}
			seen[key] = true
			tsList = append(tsList, e.Ts)
			if (e.NodeName == "gw-a") != (e.NodeID == idA) || !strings.HasPrefix(e.ID, e.NodeID+":access:") {
				t.Fatalf("identité de passerelle incohérente : %+v", e)
			}
		}
		if !p.HasMore {
			break
		}
		cursor = p.Cursor
	}
	if len(seen) != 40 {
		t.Fatalf("%d lignes parcourues, attendu 40", len(seen))
	}
	for i := 1; i < len(tsList); i++ {
		if tsList[i] > tsList[i-1] {
			t.Fatalf("ordre rompu entre %s et %s", tsList[i-1], tsList[i])
		}
	}
}

func TestMergedSearchCanBeRestrictedToOneGateway(t *testing.T) {
	_, _, admin := twoGateways(t)
	p := admin.list(t, url.Values{"node_id": {idB}, "page_size": {"100"}})
	if len(p.Entries) != 20 {
		t.Fatalf("%d lignes, attendu 20", len(p.Entries))
	}
	for _, e := range p.Entries {
		if e.NodeName != "gw-b" {
			t.Fatalf("ligne d'une autre passerelle : %+v", e)
		}
	}
	if byName := admin.list(t, url.Values{"node_name": {"gw-a"}, "page_size": {"100"}}); len(byName.Entries) != 20 {
		t.Fatalf("par nom : %d lignes", len(byName.Entries))
	}
}

// Une passerelle éteinte n'empêche pas la page : ses lignes manquent, et la réponse le dit.
func TestMergedSearchReportsAGatewayThatIsDown(t *testing.T) {
	_, b, admin := twoGateways(t)
	b.srv.Close()
	p := admin.list(t, url.Values{"page_size": {"100"}})
	if len(p.Entries) != 20 {
		t.Fatalf("%d lignes, attendu celles de gw-a seule", len(p.Entries))
	}
	if len(p.Unreachable) != 1 || p.Unreachable[0].NodeName != "gw-b" || p.Unreachable[0].Error == "" {
		t.Fatalf("injoignables = %+v", p.Unreachable)
	}
}

func TestMergedSearchAppliesFiltersOnEveryGateway(t *testing.T) {
	a, b, _ := twoGateways(t)
	a.add(time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC), 3, func(i int, e *logstore.Entry) { e.Status = 403; e.Domain = "secret.example.com" })
	b.add(time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC), 2, func(i int, e *logstore.Entry) { e.Status = 403; e.Domain = "secret.example.com" })
	admin := newSearchAdmin(t, a, b)
	p := admin.list(t, url.Values{"status": {"403"}, "page_size": {"100"}})
	if len(p.Entries) != 5 {
		t.Fatalf("%d refus, attendu 5", len(p.Entries))
	}
	if p := admin.list(t, url.Values{"domain": {"secret.example.com"}, "date_from": {"2026-10-21T10:30:00Z"}, "page_size": {"100"}}); len(p.Entries) != 5 {
		t.Fatalf("domaine + période : %d lignes", len(p.Entries))
	}
	rec := admin.do(http.MethodGet, "/api/v1/logs", url.Values{"source": {"edge"}, "date_from": {"hier"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("date illisible : code %d, attendu 400", rec.Code)
	}
	if rec := admin.do(http.MethodGet, "/api/v1/logs", url.Values{"source": {"edge"}, "cursor": {"???"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("jeton corrompu : code %d, attendu 400", rec.Code)
	}
}

func TestMergedHistogramAndFacetsAddTheGatewaysUp(t *testing.T) {
	_, _, admin := twoGateways(t)
	rec := admin.do(http.MethodGet, "/api/v1/logs/histogram", url.Values{"source": {"edge"}, "bucket": {"day"}, "date_from": {"2026-10-20T00:00:00Z"}}, nil)
	var h struct {
		Points []struct {
			Total int64 `json:"total"`
		} `json:"points"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &h) != nil {
		t.Fatalf("histogramme : %d %s", rec.Code, rec.Body.String())
	}
	var sum int64
	for _, p := range h.Points {
		sum += p.Total
	}
	if sum != 40 {
		t.Fatalf("%d entrées dans l'histogramme, attendu 40", sum)
	}

	rec = admin.do(http.MethodGet, "/api/v1/logs/facets", url.Values{"source": {"edge"}, "fields": {"domain,node_name,method"}}, nil)
	var resp struct {
		Facets map[string][]struct {
			Value string `json:"value"`
			Count int64  `json:"count"`
		} `json:"facets"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
		t.Fatalf("facettes : %d %s", rec.Code, rec.Body.String())
	}
	f := resp.Facets
	if d := f["domain"]; len(d) != 1 || d[0].Count != 40 {
		t.Fatalf("domaines = %+v", d)
	}
	if n := f["node_name"]; len(n) != 2 || n[0].Count != 20 || n[1].Count != 20 {
		t.Fatalf("passerelles = %+v", n)
	}
}

func TestMergedExportContainsEveryGatewaysLines(t *testing.T) {
	_, _, admin := twoGateways(t)
	rec := admin.do(http.MethodGet, "/api/v1/logs/export", url.Values{"source": {"edge"}, "format": {"csv"}}, nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export : %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 41 { // l'en-tête et 40 lignes
		t.Fatalf("%d lignes CSV, attendu 41", len(lines))
	}
	if !strings.Contains(rec.Body.String(), "gw-a") || !strings.Contains(rec.Body.String(), "gw-b") {
		t.Fatal("l'export doit nommer les deux passerelles")
	}
	js := admin.do(http.MethodGet, "/api/v1/logs/export", url.Values{"source": {"edge"}}, nil)
	var arr []map[string]any
	if js.Code != http.StatusOK || json.Unmarshal(js.Body.Bytes(), &arr) != nil || len(arr) != 40 {
		t.Fatalf("export JSON : %d, %d lignes", js.Code, len(arr))
	}
}

// L'IP réelle d'une ligne pseudonymisée se révèle chez la passerelle qui la garde, par la référence de la ligne.
func TestRevealGoesToTheGatewayThatOwnsTheLine(t *testing.T) {
	a, b, _ := twoGateways(t)
	a.add(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), 1, func(i int, e *logstore.Entry) {
		e.IP, e.RealIP, e.IPTruncated, e.Path = "203.0.113.0", "203.0.113.42", true, "/secret-a"
	})
	b.add(time.Date(2026, 10, 21, 12, 0, 1, 0, time.UTC), 1, func(i int, e *logstore.Entry) {
		e.IP, e.RealIP, e.IPTruncated, e.Path = "203.0.113.0", "198.51.100.77", true, "/secret-b"
	})
	admin := newSearchAdmin(t, a, b)
	p := admin.list(t, url.Values{"search": {"secret"}, "page_size": {"10"}})
	if len(p.Entries) != 2 {
		t.Fatalf("%d lignes pseudonymisées, attendu 2", len(p.Entries))
	}
	reveal := func(ref, reason string) (int, string) {
		rec := admin.do(http.MethodPost, "/api/v1/logs/reveal-ip", nil, map[string]any{"entry_ref": ref, "reason": reason})
		var out struct {
			IP string `json:"ip"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.IP
	}
	for _, e := range p.Entries {
		want := map[string]string{"/secret-a": "203.0.113.42", "/secret-b": "198.51.100.77"}[e.Path]
		if code, ip := reveal(e.ID, "demande RGPD"); code != http.StatusOK || ip != want {
			t.Errorf("%s : code %d, IP %q, attendu %q", e.Path, code, ip, want)
		}
	}
	if code, _ := reveal(p.Entries[0].ID, "   "); code != http.StatusBadRequest {
		t.Errorf("sans motif : code %d, attendu 400", code)
	}
	if code, _ := reveal("pas-une-reference", "motif"); code != http.StatusBadRequest {
		t.Errorf("référence invalide : code %d, attendu 400", code)
	}
	var audit int
	_ = admin.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'gdpr_reveal_ip'`).Scan(&audit)
	if audit != 2 {
		t.Errorf("%d révélations dans l'audit de l'Admin, attendu 2", audit)
	}
}

// writeAdminLines écrit dans la base de l'Admin des lignes qui lui sont propres (audit, requêtes de son API).
func (a *searchAdmin) writeAdminLines(t *testing.T, at time.Time, n int) {
	t.Helper()
	store := logs.New(a.db)
	for i := 0; i < n; i++ {
		store.Write(logs.Entry{
			Ts: at.Add(time.Duration(i) * time.Second), Level: "info", Component: "admin", Domain: "admin.example.com",
			Method: "GET", Path: fmt.Sprintf("/api/v1/admin-%d", i), Status: 200, IP: "10.0.0.9",
		})
	}
}

// Les lignes propres de l'Admin (component=admin) entrent dans la page fusionnée, à leur date, avec celles des
// passerelles ; un filtre qui ne vise que l'Admin n'interroge aucune passerelle ; viser une passerelle les exclut.
func TestMergedSearchIncludesTheAdminsOwnLines(t *testing.T) {
	a, b, _ := twoGateways(t)
	admin := newSearchAdmin(t, a, b)
	admin.writeAdminLines(t, time.Date(2026, 10, 21, 10, 0, 5, 500000000, time.UTC), 4) // au milieu des lignes des passerelles

	all := admin.list(t, url.Values{"page_size": {"200"}})
	adminLines, gw := 0, 0
	for _, e := range all.Entries {
		if strings.HasPrefix(e.ID, "admin:") {
			adminLines++
			if e.NodeName != "admin" {
				t.Errorf("ligne de l'Admin avec la passerelle %q", e.NodeName)
			}
		} else {
			gw++
		}
	}
	if adminLines != 4 || gw != 40 {
		t.Fatalf("%d lignes de l'Admin et %d des passerelles, attendu 4 et 40", adminLines, gw)
	}
	for i := 1; i < len(all.Entries); i++ {
		if all.Entries[i].Ts > all.Entries[i-1].Ts {
			t.Fatalf("ordre rompu entre %s et %s", all.Entries[i-1].Ts, all.Entries[i].Ts)
		}
	}
	// Pagination par petites pages : chaque ligne une fois, Admin comprise.
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 40; pages++ {
		q := url.Values{"page_size": {"6"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		p := admin.list(t, q)
		for _, e := range p.Entries {
			if seen[e.ID] {
				t.Fatalf("ligne en double : %s", e.ID)
			}
			seen[e.ID] = true
		}
		if !p.HasMore {
			break
		}
		cursor = p.Cursor
	}
	if len(seen) != 44 {
		t.Fatalf("%d lignes parcourues, attendu 44", len(seen))
	}

	if only := admin.list(t, url.Values{"component": {"admin"}, "page_size": {"100"}}); len(only.Entries) != 4 {
		t.Fatalf("component=admin : %d lignes, attendu 4", len(only.Entries))
	}
	if onGW := admin.list(t, url.Values{"node_id": {idA}, "page_size": {"100"}}); len(onGW.Entries) != 20 {
		t.Fatalf("une passerelle visée : %d lignes, attendu 20 sans celles de l'Admin", len(onGW.Entries))
	}
	if edgeOnly := admin.list(t, url.Values{"component": {"edge"}, "page_size": {"100"}}); len(edgeOnly.Entries) != 40 {
		t.Fatalf("component=edge : %d lignes, attendu 40", len(edgeOnly.Entries))
	}
}

func TestMergedHistogramAndFacetsIncludeTheAdminsOwnLines(t *testing.T) {
	a, b, _ := twoGateways(t)
	admin := newSearchAdmin(t, a, b)
	admin.writeAdminLines(t, time.Date(2026, 10, 21, 10, 0, 5, 0, time.UTC), 5)

	rec := admin.do(http.MethodGet, "/api/v1/logs/histogram", url.Values{"source": {"edge"}, "bucket": {"day"}, "date_from": {"2026-10-20T00:00:00Z"}}, nil)
	var h struct {
		Points []struct {
			Total int64 `json:"total"`
		} `json:"points"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &h) != nil {
		t.Fatalf("histogramme : %d %s", rec.Code, rec.Body.String())
	}
	var sum int64
	for _, p := range h.Points {
		sum += p.Total
	}
	if sum != 45 {
		t.Fatalf("%d entrées, attendu 45 (40 des passerelles et 5 de l'Admin)", sum)
	}

	rec = admin.do(http.MethodGet, "/api/v1/logs/facets", url.Values{"source": {"edge"}, "fields": {"component,node_name"}}, nil)
	var f struct {
		Facets map[string][]struct {
			Value string `json:"value"`
			Count int64  `json:"count"`
		} `json:"facets"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &f) != nil {
		t.Fatalf("facettes : %d %s", rec.Code, rec.Body.String())
	}
	byNode := map[string]int64{}
	for _, n := range f.Facets["node_name"] {
		byNode[n.Value] = n.Count
	}
	if byNode["admin"] != 5 || byNode["gw-a"] != 20 || byNode["gw-b"] != 20 {
		t.Fatalf("lignes par nœud = %v", byNode)
	}
	byComp := map[string]int64{}
	for _, c := range f.Facets["component"] {
		byComp[c.Value] = c.Count
	}
	if byComp["admin"] != 5 || byComp["edge"] != 40 {
		t.Fatalf("lignes par composant = %v", byComp)
	}
}

// L'export RGPD d'une IP rassemble ses lignes dans la base de chaque passerelle, et nomme celles qui n'ont pas répondu.
func TestSubjectExportReadsTheGatewayLogs(t *testing.T) {
	a := newSearchGW(t, t.TempDir(), "id-a", "gw-a")
	b := newSearchGW(t, t.TempDir(), "id-b", "gw-b")
	start := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	other := func(i int, e *logstore.Entry) {
		if i >= 6 {
			e.IP = "203.0.113.77"
		}
	}
	a.add(start, 10, other)
	b.add(start.Add(time.Hour), 8, other)
	admin := newSearchAdmin(t, a, b)

	export := func() (int, []string, int) {
		rec := admin.do(http.MethodPost, "/api/v1/logs/subject-export", nil, map[string]string{"ip": "203.0.113.77", "reason": "test"})
		if rec.Code != http.StatusOK {
			t.Fatalf("code %d : %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Logs            []map[string]any `json:"logs"`
			GatewaysMissing []string         `json:"gateways_missing"`
			Truncated       bool             `json:"logs_truncated"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return len(out.Logs), out.GatewaysMissing, len(out.Logs)
	}
	if n, missing, _ := export(); n != 4+2 || len(missing) != 0 {
		t.Fatalf("%d lignes, passerelles manquantes %v, attendu 6 et aucune", n, missing)
	}
	b.srv.Close()
	n, missing, _ := export()
	if n != 4 || len(missing) != 1 || missing[0] != "gw-b" {
		t.Fatalf("%d lignes, passerelles manquantes %v, attendu 4 et gw-b", n, missing)
	}
}

// La passerelle rejoue ses accès contre les deux configurations avec le moteur d'Ephor : le rapport est celui que
// threat.Simulate donne sur les mêmes événements.
func TestEphorSimulationRunsOnTheGatewayTraffic(t *testing.T) {
	gw := newSearchGW(t, t.TempDir(), "id-a", "gw-a")
	admin := newSearchAdmin(t, gw)
	now := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	type line struct {
		ip     string
		status int
		path   string
	}
	var lines []line
	for i := 0; i < 40; i++ {
		lines = append(lines, line{"198.51.100.10", 404, fmt.Sprintf("/probe/%d", i)})
		lines = append(lines, line{"198.51.100.20", 200, "/home"})
		if i%4 == 0 {
			lines = append(lines, line{"198.51.100.30", []int{404, 200}[i%8/4], "/maybe"})
		}
	}
	var events []threat.SimEvent
	for i, l := range lines {
		ts := now.Add(time.Duration(i) * 3 * time.Second)
		gw.logStore.Add(logstore.KindAccess, logstore.Entry{Ts: ts, Level: "info", Component: "edge", Domain: "app.example.com",
			Method: "GET", Path: l.path, Status: l.status, IP: l.ip})
		events = append(events, threat.SimEvent{Time: ts, IP: l.ip, Path: l.path, Status: l.status})
	}
	gw.logStore.Flush()
	override := map[string]any{"enabled": true, "error_threshold": 5, "error_window": "10m"}
	got, err := api.SimulateEphor(context.Background(), admin.db, &prismedge.Source{DB: admin.db}, "threat_config", override, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if got["gateways"] != 1 {
		t.Fatalf("la simulation n'a pas tourné sur la passerelle : %v", got["gateways"])
	}
	var candidate threat.Config
	b, _ := json.Marshal(override)
	if err := json.Unmarshal(b, &candidate); err != nil {
		t.Fatal(err)
	}
	wantCurrent, wantCandidate := threat.Simulate(threat.Config{}, events), threat.Simulate(candidate, events)
	if wantCandidate.Blocked == 0 || wantCandidate.BlockedIPs == 0 {
		t.Fatalf("la config candidate ne bloque rien : le jeu d'essai ne prouve rien (%+v)", wantCandidate)
	}
	if got["events_replayed"] != len(events) {
		t.Errorf("%v événements rejoués, attendu %d", got["events_replayed"], len(events))
	}
	if !reflect.DeepEqual(got["current"], wantCurrent) || !reflect.DeepEqual(got["candidate"], wantCandidate) {
		t.Errorf("rapports :\n passerelle %+v / %+v\n moteur %+v / %+v", got["current"], got["candidate"], wantCurrent, wantCandidate)
	}
	// Sans passerelle, il n'y a rien à rejouer.
	if _, err := admin.db.Exec(`DELETE FROM tokens`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.SimulateEphor(context.Background(), admin.db, &prismedge.Source{DB: admin.db}, "threat_config", override, 1, ""); err == nil {
		t.Error("une simulation sans passerelle devrait être refusée")
	}
}

// L'effacement d'une IP part de l'Admin vers chaque passerelle, qui répond avec ce qu'elle a supprimé (accès, logs
// système, lignes pseudonymisées) : c'est la preuve ; une passerelle qui ne répond pas est annoncée « pending ».
func TestEraseIPReportsWhatEachGatewayDeleted(t *testing.T) {
	a := newSearchGW(t, t.TempDir(), "id-a", "gw-a")
	b := newSearchGW(t, t.TempDir(), "id-b", "gw-b")
	start := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	const target, other = "203.0.113.77", "198.51.100.1"
	a.add(start, 4, func(i int, e *logstore.Entry) {
		if i < 2 {
			e.IP = target
		}
	})
	// Une ligne pseudonymisée (IP tronquée, réelle chiffrée), une ligne système qui porte l'IP.
	a.logStore.Add(logstore.KindAccess, logstore.Entry{Ts: start.Add(time.Hour), Level: "info", Component: "edge", Domain: "app.example.com", Method: "GET",
		Path: "/pseudo", Status: 200, IP: "203.0.113.0", RealIP: target, IPTruncated: true})
	a.logStore.Add(logstore.KindSystem, logstore.Entry{Ts: start.Add(time.Hour), Level: "warn", Component: "edge", Message: "refus", IP: target})
	a.logStore.Flush()
	b.add(start, 3, func(i int, e *logstore.Entry) { e.IP = target })
	admin := newSearchAdmin(t, a, b)
	b.srv.Close()

	rec := admin.do(http.MethodDelete, "/api/v1/logs/by-ip/"+target, nil, map[string]string{"reason": "Art. 17"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d : %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Gateways []struct {
			NodeName string `json:"node_name"`
			Status   string `json:"status"`
			LogLines int64  `json:"log_lines"`
		} `json:"gateways"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	by := map[string]int64{}
	status := map[string]string{}
	for _, g := range out.Gateways {
		by[g.NodeName], status[g.NodeName] = g.LogLines, g.Status
	}
	// gw-a : 2 accès en clair + 1 pseudonymisé + 1 ligne système.
	if status["gw-a"] != "erased" || by["gw-a"] != 4 || status["gw-b"] != "pending" {
		t.Fatalf("passerelles : %+v", out.Gateways)
	}
	// Plus rien de l'IP chez gw-a : ni par l'adresse, ni par son empreinte, ni dans les logs système ; l'autre IP reste.
	for _, kind := range []logstore.Kind{logstore.KindAccess, logstore.KindSystem} {
		page, err := a.logStore.Search(context.Background(), logstore.Query{Kinds: []logstore.Kind{kind}, IP: target, Limit: 100})
		if err != nil || len(page.Rows) != 0 {
			t.Errorf("%s : %d lignes de l'IP effacée subsistent (%v)", kind, len(page.Rows), err)
		}
	}
	if page, _ := a.logStore.Search(context.Background(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, IP: other, Limit: 100}); len(page.Rows) != 2 {
		t.Errorf("les lignes des autres IP ont été touchées : %d, attendu 2", len(page.Rows))
	}
	// Une valeur qui n'est pas une adresse est refusée : elle effacerait toutes les lignes pseudonymisées.
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/internal/v1/logs/erase", strings.NewReader(`{"ip":"[pseudonymisé]"}`))
	req.Header.Set("Authorization", "Bearer tok-gw-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("valeur non-IP : code %d, attendu 400", resp.StatusCode)
	}
}
