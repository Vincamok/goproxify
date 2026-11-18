// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestBoussoleIsAValidTheme(t *testing.T) {
	if got := NormalizeTheme(" Boussole "); got != ThemeBoussole {
		t.Fatalf("NormalizeTheme(boussole) = %q", got)
	}
	found := false
	for _, th := range Themes() {
		found = found || th == ThemeBoussole
	}
	if !found {
		t.Fatal("boussole absent de Themes()")
	}
}

func TestBoussolePageIsServedForThatThemeOnly(t *testing.T) {
	cfg := &Config{Enabled: true, PublicHost: "access.example.fr", Theme: ThemeBoussole,
		Views: []View{{Slug: "presta", Title: "Espace presta", Theme: "ocean"}, {Slug: "ops", Title: "Espace ops", Tagline: "Exploitation", Theme: ThemeBoussole}}}
	store := NewStore(t.TempDir()+"/p.gpx", "k")
	h := NewHTTPServer(cfg, store, NewSessionManager(), nil, nil).Handler()
	cases := []struct {
		path       string
		wantBoss   bool
		wantTitle  string
		wantTagSub string
	}{
		{"/", true, DefaultViewTitle, DefaultViewTagline},
		{"/ops", true, "Espace ops", "Exploitation"},
		{"/presta", false, "Espace presta", ""},
	}
	for _, c := range cases {
		rr := doReq(h, http.MethodGet, c.path, "access.example.fr", "", "", "")
		body := rr.Body.String()
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: code %d", c.path, rr.Code)
		}
		if is := strings.Contains(body, "Boussole : un lanceur"); is != c.wantBoss {
			t.Errorf("%s: page boussole = %v, attendu %v", c.path, is, c.wantBoss)
		}
		if !strings.Contains(body, c.wantTitle) {
			t.Errorf("%s: titre %q absent", c.path, c.wantTitle)
		}
		if c.wantTagSub != "" && !strings.Contains(body, c.wantTagSub) {
			t.Errorf("%s: sous-titre %q absent", c.path, c.wantTagSub)
		}
		if strings.Contains(body, "__PORTAL_") {
			t.Errorf("%s: placeholder non remplacé", c.path)
		}
	}
	rr := doReq(h, http.MethodGet, "/ops", "access.example.fr", "", "", "")
	if !strings.Contains(rr.Body.String(), `"slug":"ops"`) || !strings.Contains(rr.Body.String(), `data-theme="boussole"`) {
		t.Error("la vue (slug, clé) et le thème doivent être injectés dans la page")
	}
}

// Toute route appelée par l'interface boussole doit exister dans le serveur : une faute de frappe dans un chemin serait sinon
// invisible jusqu'au clic.
func TestBoussoleOnlyCallsRealRoutes(t *testing.T) {
	src, err := os.ReadFile("httpserver.go")
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("(?:GET|POST|PUT|DELETE) (/api/[^"]*)"`).FindAllStringSubmatch(string(src), -1) {
		routes = append(routes, regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(m[1], ""))
	}
	if len(routes) < 20 {
		t.Fatalf("routes non lues (%d)", len(routes))
	}
	calls := regexp.MustCompile(`'(/api/[^']*)'`).FindAllStringSubmatch(boussoleIndexHTML, -1)
	if len(calls) < 20 {
		t.Fatalf("appels API non lus (%d)", len(calls))
	}
	for _, c := range calls {
		lit, ok := c[1], false
		for _, r := range routes {
			if r == lit || (strings.HasSuffix(lit, "/") && strings.HasPrefix(r, lit)) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("l'interface appelle %q, route inconnue", lit)
		}
	}
}

func TestBoussoleKeepsSessionKeysOfTheStandardUI(t *testing.T) {
	for _, frag := range []string{"'gpx_portal_tok:' + VIEW.key", "'gpx_portal_user:' + VIEW.key", "'X-Portal-View': VIEW.slug", "\\x00gpx-resize:", "sso_2fa", "login_required"} {
		if !strings.Contains(boussoleIndexHTML, frag) {
			t.Errorf("boussole doit garder %q (changer de thème ne doit ni déconnecter ni casser le terminal)", frag)
		}
	}
}
