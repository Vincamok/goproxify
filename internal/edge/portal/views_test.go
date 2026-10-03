// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func viewsFixture(t *testing.T) (*HTTPServer, http.Handler) {
	t.Helper()
	yes := true
	cfg := &Config{
		Enabled: true, PublicHost: "access.example.fr", Theme: "clair",
		Views: []View{
			{Slug: "prestataire", Title: "Espace prestataires", Tagline: "Accès externe", Theme: "ocean",
				AllowedTags: []string{"presta"}, TargetTags: []string{"presta"}, Require2FA: &yes},
			{Slug: "interne", Theme: "sombre", TargetTags: []string{"interne", "presta"}},
			{Host: "presta.example.fr", Title: "Hôte dédié", Theme: "foret"},
		},
	}
	store := NewStore(t.TempDir()+"/p.gpx", "k")
	pw, _ := HashPassword("secret-pass")
	now := time.Now().UTC().Format(time.RFC3339)
	for _, u := range []UserRecord{
		{ID: "u-int", Username: "alice", PasswordHash: pw, CreatedAt: now, Status: UserStatusActive, Tags: []string{"interne"}},
		{ID: "u-pre", Username: "bob", PasswordHash: pw, CreatedAt: now, Status: UserStatusActive, Tags: []string{"presta"}},
	} {
		if err := store.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.SetCatalog([]CatalogTarget{
		{ID: "t-int", Name: "Interne", Kind: TargetSSH, Host: "10.0.0.1", Tags: []string{"interne"}},
		{ID: "t-pre", Name: "Presta", Kind: TargetSSH, Host: "10.0.0.2", Tags: []string{"presta"}},
	})
	h := NewHTTPServer(cfg, store, NewSessionManager(), nil, nil)
	h.grants = NewGrantSet()
	return h, h.Handler()
}

func doReq(h http.Handler, method, path, host, view, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if host != "" {
		req.Host = host
	}
	if view != "" {
		req.Header.Set("X-Portal-View", view)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestViewsIndexPerURL(t *testing.T) {
	_, h := viewsFixture(t)
	cases := []struct{ path, host, wantTitle, wantTheme string }{
		{"/", "access.example.fr", DefaultViewTitle, "clair"},
		{"/prestataire", "access.example.fr", "Espace prestataires", "ocean"},
		{"/interne/", "access.example.fr", DefaultViewTitle, "sombre"},
		{"/", "presta.example.fr", "Hôte dédié", "foret"},
		{"/inconnu", "access.example.fr", DefaultViewTitle, "clair"},
	}
	for _, c := range cases {
		rr := doReq(h, http.MethodGet, c.path, c.host, "", "", "")
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<h1>"+c.wantTitle+"</h1>") || !strings.Contains(body, "var t = '"+c.wantTheme+"';") {
			t.Errorf("%s %s: code=%d title=%q theme=%q attendus", c.host, c.path, rr.Code, c.wantTitle, c.wantTheme)
		}
		if strings.Contains(body, "__PORTAL_") {
			t.Errorf("%s: placeholder non remplacé", c.path)
		}
	}
}

func login(t *testing.T, h http.Handler, view, user string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": "secret-pass"})
	return doReq(h, http.MethodPost, "/api/login", "access.example.fr", view, "", string(b))
}

func tokenOf(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("pas de token: %d %s", rr.Code, rr.Body.String())
	}
	return out.Token
}

func TestViewsLoginRestrictedByGroup(t *testing.T) {
	_, h := viewsFixture(t)
	if rr := login(t, h, "prestataire", "alice"); rr.Code != http.StatusForbidden {
		t.Fatalf("alice (interne) sur /prestataire: %d, attendu 403", rr.Code)
	}
	if rr := login(t, h, "interne", "alice"); rr.Code != 200 {
		t.Fatalf("alice sur /interne: %d %s", rr.Code, rr.Body.String())
	}
	// /prestataire exige la 2FA : bob n'en a pas.
	if rr := login(t, h, "prestataire", "bob"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "2FA") {
		t.Fatalf("bob sans 2FA sur /prestataire: %d %s", rr.Code, rr.Body.String())
	}
	if rr := login(t, h, "", "bob"); rr.Code != 200 {
		t.Fatalf("bob sur le portail par défaut (pas de restriction): %d", rr.Code)
	}
}

func TestViewsTokenBoundToView(t *testing.T) {
	_, h := viewsFixture(t)
	tok := tokenOf(t, login(t, h, "interne", "alice"))
	if rr := doReq(h, http.MethodGet, "/api/me", "access.example.fr", "interne", tok, ""); rr.Code != 200 {
		t.Fatalf("me sur la vue d'émission: %d", rr.Code)
	}
	for _, v := range []string{"", "prestataire"} {
		if rr := doReq(h, http.MethodGet, "/api/me", "access.example.fr", v, tok, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("token réutilisé sur la vue %q: %d, attendu 401", v, rr.Code)
		}
	}
}

func TestViewsCatalogFilter(t *testing.T) {
	_, h := viewsFixture(t)
	names := func(rr *httptest.ResponseRecorder) string {
		var out struct {
			Targets []struct{ ID string } `json:"targets"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		var ids []string
		for _, x := range out.Targets {
			ids = append(ids, x.ID)
		}
		return strings.Join(ids, ",")
	}
	// bob (tag presta) sur le portail par défaut : seulement t-pre ; alice : seulement t-int.
	tokBob := tokenOf(t, login(t, h, "", "bob"))
	if got := names(doReq(h, http.MethodGet, "/api/targets", "access.example.fr", "", tokBob, "")); got != "t-pre" {
		t.Fatalf("bob par défaut: %q", got)
	}
	tokAlice := tokenOf(t, login(t, h, "interne", "alice"))
	if got := names(doReq(h, http.MethodGet, "/api/targets", "access.example.fr", "interne", tokAlice, "")); got != "t-int" {
		t.Fatalf("alice /interne: %q", got)
	}
}

func TestViewsAuthInfoPerView(t *testing.T) {
	_, h := viewsFixture(t)
	rr := doReq(h, http.MethodGet, "/api/auth-info", "access.example.fr", "prestataire", "", "")
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["require_2fa"] != true {
		t.Fatalf("auth-info /prestataire: %v", out)
	}
	rr = doReq(h, http.MethodGet, "/api/auth-info", "access.example.fr", "", "", "")
	out = map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["require_2fa"] != false {
		t.Fatalf("auth-info défaut: %v", out)
	}
}

func TestValidateViews(t *testing.T) {
	ok := []View{{Slug: "prestataire"}, {Slug: "interne", Host: "x.example.fr"}, {Host: "y.example.fr"}}
	if err := ValidateViews(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]View{
		"vide":      {{Name: "x"}},
		"réservé":   {{Slug: "api"}},
		"majuscule": {{Slug: "Presta Taire"}},
		"doublon":   {{Slug: "a"}, {Slug: "A"}},
		"hôte":      {{Host: "pas d'hôte"}},
	} {
		if err := ValidateViews(bad); err == nil {
			t.Errorf("%s: erreur attendue", name)
		}
	}
}

func TestViewHosts(t *testing.T) {
	c := &Config{PublicHost: "A.example.fr", Views: []View{{Slug: "x", Host: "a.example.fr"}, {Host: "b.example.fr"}, {Slug: "y", Host: "b.example.fr"}}}
	got := c.ViewHosts()
	if len(got) != 1 || got[0] != "b.example.fr" {
		t.Fatalf("ViewHosts = %v", got)
	}
}
