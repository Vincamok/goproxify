// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/sqltime"
)

func TestTemplatePath(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-login.php?redirect=/x":               "/wp-login.php",
		"/WP-Admin/":                              "/wp-admin/",
		"/users/42/orders/9":                      "/users/{int}/orders/{int}",
		"/u/123e4567-e89b-12d3-a456-426614174000": "/u/{uuid}",
		"/files/0123456789abcdef0123/x":           "/files/{hex}/x",
		"/mail/john@example.com":                  "/mail/{var}",
		"/a/2026-11-07":                           "/a/{date}",
		"/reset/aB3dE5gH7jK9mN1pQ3sT5v":           "/reset/{token}",
		"/../../etc/passwd":                       "/../../etc/passwd",
		"/%2e%2e/%2e%2e/etc/passwd":               "/../../etc/passwd",
		"relative":                                "",
		"":                                        "",
	} {
		if got := TemplatePath(in); got != want {
			t.Errorf("TemplatePath(%q) = %q, attendu %q", in, got, want)
		}
	}
	if got := TemplatePath("/" + strings.Repeat("a/", 40)); strings.Count(got, "/") > maxSegments+1 {
		t.Errorf("segments non bornés : %q", got)
	}
}

func TestProtectedAndSpecific(t *testing.T) {
	for _, p := range []string{"/", "/robots.txt", "/favicon.ico", "/.well-known/acme-challenge/{token}", "/healthz", "/api"} {
		if !Protected(p) {
			t.Errorf("%q devrait être protégé", p)
		}
	}
	for _, p := range []string{"/.env", "/wp-login.php", "/vendor/phpunit/x"} {
		if Protected(p) {
			t.Errorf("%q ne devrait pas être protégé", p)
		}
	}
	for p, want := range map[string]bool{"/": false, "/{int}": false, "/{var}/{int}": false, "/.env": true, "/a/{int}": true} {
		if Specific(p) != want {
			t.Errorf("Specific(%q) = %v", p, !want)
		}
	}
}

func TestNormalizeUA(t *testing.T) {
	for in, want := range map[string]string{
		"sqlmap/1.7.2#stable (https://sqlmap.org)":                    "sqlmap/1.x",
		"Mozilla/5.0 (compatible; Nuclei - Open-source project)":      "nuclei",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120": "",
		"curl/8.4.0":           "",
		"python-requests/2.31": "",
		"":                     "",
	} {
		if got := NormalizeUA(in); got != want {
			t.Errorf("NormalizeUA(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestPathFamily(t *testing.T) {
	for p, want := range map[string]Family{
		"/.env":                  FamilyConfigLeak,
		"/.git/config":           FamilyConfigLeak,
		"/backup.zip":            FamilyConfigLeak,
		"/wp-content/plugins/x":  FamilyCMSProbe,
		"/phpmyadmin/index.php":  FamilyAdminProbe,
		"/cgi-bin/luci":          FamilyExploitCVE,
		"/../../etc/passwd":      FamilyLFI,
		"/zzz-nothing-here.html": FamilyScanner,
	} {
		if got := PathFamily(p); got != want {
			t.Errorf("PathFamily(%q) = %q, attendu %q", p, got, want)
		}
	}
}

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func lines(n int, method, path string, status int, waf ...string) []Line {
	out := make([]Line, n)
	for i := range out {
		out[i] = Line{Ts: t0.Add(time.Duration(i) * time.Second), Domain: "a.example", Method: method, Path: path, Status: status, WAF: waf}
	}
	return out
}

func profiles(d Dossier) []Profile {
	var out []Profile
	for _, p := range d.Profiles {
		out = append(out, p.Profile)
	}
	return out
}

func has(ps []Profile, p Profile) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func TestBuildDossierProfiles(t *testing.T) {
	ban := BanInfo{IP: "203.0.113.5", At: t0, Source: "fail2ban", UserAgent: "sqlmap/1.7"}

	var scan []Line
	for i := 0; i < 15; i++ {
		scan = append(scan, lines(1, "GET", fmt.Sprintf("/probe-%d.php", i), 404)...)
	}
	d := BuildDossier(ban, scan)
	if !has(profiles(d), ProfileScanner) || d.DistinctPaths != 15 || d.Statuses["4xx"] != 15 {
		t.Errorf("scanner : %+v", d.Profiles)
	}
	if d.UAFamily != "sqlmap/1.x" || d.Families[len(d.Families)-1] != FamilyOffensiveClient && !contains(d.Families, FamilyOffensiveClient) {
		t.Errorf("famille d'outil : %q %v", d.UAFamily, d.Families)
	}

	d = BuildDossier(ban, lines(20, "POST", "/wp-login.php", 200))
	if !has(profiles(d), ProfileBruteforcer) {
		t.Errorf("force brute : %+v", d.Profiles)
	}

	d = BuildDossier(ban, append(lines(3, "GET", "/search?q=1' or 1=1", 403, "sqli"), lines(1, "GET", "/", 200)...))
	if profiles(d)[0] != ProfileExploiter || !contains(d.Families, FamilySQLi) {
		t.Errorf("exploitation : %+v %v", d.Profiles, d.Families)
	}

	var enum []Line
	for i := 0; i < 40; i++ {
		enum = append(enum, lines(1, "GET", fmt.Sprintf("/api/users/%d", i), 404)...)
	}
	if d = BuildDossier(ban, enum); !has(profiles(d), ProfileEnumerator) {
		t.Errorf("énumération : %+v", d.Profiles)
	}

	d = BuildDossier(ban, lines(3, "GET", "/", 200))
	if profiles(d)[0] != ProfileUnclassified {
		t.Errorf("rien à dire : %+v", d.Profiles)
	}

	d = BuildDossier(ban, []Line{{Ts: t0, Path: "/x", Status: 0}})
	if d.Requests != 0 {
		t.Errorf("une ligne système compte comme requête : %d", d.Requests)
	}
}

func contains(fs []Family, f Family) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

// fakeTraffic rend, par IP, des lignes fixes et, par préfixe, un trafic global fixe.
type fakeTraffic struct {
	byIP    map[string][]Line
	reach   map[string]Reach
	total   int64
	failing bool
}

func (f *fakeTraffic) Lines(_ context.Context, ip string, _, _ time.Time) ([]Line, error) {
	if f.failing {
		return nil, ErrDegraded
	}
	return f.byIP[ip], nil
}
func (f *fakeTraffic) PathReach(_ context.Context, prefix string, _, _ time.Time) (Reach, error) {
	if f.failing {
		return Reach{}, ErrDegraded
	}
	return f.reach[prefix], nil
}
func (f *fakeTraffic) TotalRequests(context.Context, time.Time, time.Time) (int64, error) {
	if f.failing {
		return 0, ErrDegraded
	}
	return f.total, nil
}

func testMiner(t *testing.T, tr Traffic) *Miner {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE security_ban_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, domain TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT 'banned',
		reason TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'native', ban_id TEXT NOT NULL DEFAULT '',
		edge_name TEXT NOT NULL DEFAULT '', signals TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	m := &Miner{Store: &Store{DB: db}, Traffic: tr, Cfg: cfg, Now: func() time.Time { return t0.Add(10 * 24 * time.Hour) }}
	return m
}

func ban(t *testing.T, m *Miner, ip string, at time.Time, source, ua string) {
	t.Helper()
	if _, err := m.Store.DB.Exec(`INSERT INTO security_ban_history (ip, action, source, user_agent, created_at) VALUES (?, 'banned', ?, ?, ?)`,
		ip, source, ua, sqltime.Format(at)); err != nil {
		t.Fatal(err)
	}
}

// scene : 6 scanners, bannis sur 3 jours, qui sondent tous /.env et /robots.txt ; les visiteurs demandent /robots.txt.
func scene(t *testing.T) (*Miner, *fakeTraffic) {
	tr := &fakeTraffic{byIP: map[string][]Line{}, reach: map[string]Reach{}, total: 100_000}
	m := testMiner(t, tr)
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("203.0.113.%d", 10+i)
		at := t0.Add(time.Duration(i%3) * 24 * time.Hour)
		ban(t, m, ip, at, "fail2ban", "sqlmap/1.7")
		var ls []Line
		for _, p := range []string{"/.env", "/robots.txt", "/wp-login.php", "/"} {
			l := lines(1, "GET", p, 404)[0]
			l.Ts = at.Add(-time.Minute)
			ls = append(ls, l)
		}
		tr.byIP[ip] = ls
	}
	tr.reach["/.env"] = Reach{Requests: 6, OK: 0}
	tr.reach["/robots.txt"] = Reach{Requests: 5000, OK: 4990}
	tr.reach["/wp-login.php"] = Reach{Requests: 6 + 2000, OK: 1990}
	return m, tr
}

func TestMinerKeepsOnlyWhatDiscriminates(t *testing.T) {
	m, _ := scene(t)
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.DossiersBuilt != 6 {
		t.Fatalf("dossiers = %+v", res)
	}
	es, _, err := m.Store.Entries(context.Background(), EntryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range es {
		got[string(e.Kind)+" "+e.Value] = e
	}
	env, ok := got["path /.env"]
	if !ok {
		t.Fatalf("/.env devrait être candidat : %+v", es)
	}
	if env.DistinctIPs != 6 || env.Days != 3 || env.Family != FamilyConfigLeak || env.Lift < 50 || env.Status != StatusCandidate || env.CleanHits != 0 {
		t.Errorf("preuves de /.env : %+v", env)
	}
	if _, bad := got["path /robots.txt"]; bad {
		t.Error("/robots.txt est protégé")
	}
	if _, bad := got["path /wp-login.php"]; bad {
		t.Error("/wp-login.php est visité par des visiteurs avec succès : il ne discrimine pas")
	}
	if ua, ok := got["ua sqlmap/1.x"]; !ok || ua.Lift != LiftUnmeasured || ua.DistinctIPs != 6 {
		t.Errorf("entrée UA : %+v", ua)
	}
}

func TestMinerNeedsEnoughIPsAndDays(t *testing.T) {
	m, _ := scene(t)
	m.Cfg.MinIPs = 7
	if _, err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if es, _, _ := m.Store.Entries(context.Background(), EntryFilter{}); len(es) != 0 {
		t.Errorf("6 IP < 7 : aucune entrée attendue, %+v", es)
	}
	m.Cfg.MinIPs, m.Cfg.MinDays = 5, 4
	if _, err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if es, _, _ := m.Store.Entries(context.Background(), EntryFilter{}); len(es) != 0 {
		t.Errorf("3 jours < 4 : aucune entrée attendue, %+v", es)
	}
}

func TestMinerRejectionSurvivesRecompute(t *testing.T) {
	m, _ := scene(t)
	ctx := context.Background()
	m.Run(ctx) //nolint:errcheck
	if err := m.Store.SetStatus(ctx, KindPath, "/.env", StatusRejected); err != nil {
		t.Fatal(err)
	}
	m.Run(ctx) //nolint:errcheck
	es, _, _ := m.Store.Entries(ctx, EntryFilter{Status: "rejected"})
	if len(es) != 1 || es[0].Value != "/.env" {
		t.Errorf("le rejet doit survivre au recalcul : %+v", es)
	}
	if err := m.Store.SetStatus(ctx, KindPath, "/nope", StatusRejected); err != ErrNotFound {
		t.Errorf("entrée inconnue : %v", err)
	}
	if err := m.Store.SetStatus(ctx, KindPath, "/.env", "enforce"); err != ErrBadStatus {
		t.Errorf("l'étape 1 ne pose pas enforce : %v", err)
	}
}

func TestMinerDegradedKeepsPreviousEntries(t *testing.T) {
	m, tr := scene(t)
	ctx := context.Background()
	m.Run(ctx) //nolint:errcheck
	tr.failing = true
	res, err := m.Run(ctx)
	if err != nil || !res.Degraded {
		t.Fatalf("passage dégradé attendu : %+v %v", res, err)
	}
	if es, _, _ := m.Store.Entries(ctx, EntryFilter{Kind: "path"}); len(es) != 1 {
		t.Errorf("les entrées de chemin doivent rester quand les passerelles se taisent : %+v", es)
	}
}

func TestMinerDropsCandidateOnceVisitorsAppear(t *testing.T) {
	m, tr := scene(t)
	ctx := context.Background()
	m.Run(ctx) //nolint:errcheck
	tr.reach["/.env"] = Reach{Requests: 6 + 50, OK: 50}
	m.Run(ctx) //nolint:errcheck
	if es, _, _ := m.Store.Entries(ctx, EntryFilter{Kind: "path"}); len(es) != 0 {
		t.Errorf("un chemin désormais servi à des visiteurs doit quitter le référentiel : %+v", es)
	}
}

func TestMinerSkipsContestedPrivateAndRangeBans(t *testing.T) {
	tr := &fakeTraffic{byIP: map[string][]Line{}, reach: map[string]Reach{}}
	m := testMiner(t, tr)
	ctx := context.Background()
	ban(t, m, "203.0.113.50", t0, "fail2ban", "")
	m.Store.DB.Exec(`INSERT INTO security_ban_history (ip, action, reason, source, created_at) VALUES ('203.0.113.50','unbanned','levé à la main','native',?)`, sqltime.Format(t0.Add(time.Hour)))
	ban(t, m, "10.0.0.7", t0, "fail2ban", "")
	ban(t, m, "198.51.100.0/24", t0, "fail2ban", "")
	ban(t, m, "203.0.113.51", t0, "manual", "")
	ban(t, m, "203.0.113.52", t0, "fail2ban", "")
	m.Store.DB.Exec(`INSERT INTO security_ban_history (ip, action, reason, source, created_at) VALUES ('203.0.113.52','unbanned','expiré','native',?)`, sqltime.Format(t0.Add(time.Hour)))
	res, err := m.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.DossiersBuilt != 1 {
		t.Errorf("seul l'IP expirée normalement doit avoir un dossier : %+v", res)
	}
	ds, _, _ := m.Store.Dossiers(ctx, DossierFilter{})
	if len(ds) != 1 || ds[0].IP != "203.0.113.52" {
		t.Errorf("dossiers : %+v", ds)
	}
}

func TestMinerWaitsForAfterWindowAndBuildsOnce(t *testing.T) {
	tr := &fakeTraffic{byIP: map[string][]Line{}, reach: map[string]Reach{}}
	m := testMiner(t, tr)
	now := t0.Add(30 * time.Minute)
	m.Now = func() time.Time { return now }
	ban(t, m, "203.0.113.60", t0, "threat", "")
	if res, _ := m.Run(context.Background()); res.DossiersBuilt != 0 {
		t.Error("le dossier doit attendre la fin de la fenêtre d'après-ban")
	}
	now = t0.Add(2 * time.Hour)
	if res, _ := m.Run(context.Background()); res.DossiersBuilt != 1 {
		t.Error("dossier attendu")
	}
	if res, _ := m.Run(context.Background()); res.DossiersBuilt != 0 {
		t.Error("un ban n'a qu'un dossier")
	}
}

func TestStoreDeleteAndSummary(t *testing.T) {
	m, _ := scene(t)
	ctx := context.Background()
	m.Run(ctx) //nolint:errcheck
	sum, err := m.Store.Summary(ctx)
	if err != nil || sum.Dossiers != 6 || sum.Entries["candidate"] != 2 || sum.Profiles["unclassified"] != 6 {
		t.Errorf("synthèse : %+v %v", sum, err)
	}
	if n, _ := m.Store.DeleteDossiers(ctx, "203.0.113.10"); n != 1 {
		t.Errorf("effacement : %d", n)
	}
	if ds, total, _ := m.Store.Dossiers(ctx, DossierFilter{IP: "203.0.113.10"}); total != 0 || len(ds) != 0 {
		t.Error("dossier encore là")
	}
}
