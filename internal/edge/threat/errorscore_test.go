// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

func TestErrorScorePoints(t *testing.T) {
	c := ErrorScoreConfig{Enabled: true}
	cases := []struct {
		status int
		path   string
		want   float64
	}{
		{404, "/", 0.5}, {400, "/", 1}, {405, "/", 1},
		{401, "/", 0}, {403, "/", 0}, {429, "/", 0}, // hors score
		{418, "/", 0.5}, // code absent : poids par défaut
	}
	for _, tc := range cases {
		if got := c.points(tc.status, tc.path); got != tc.want {
			t.Errorf("%d %s : %v, attendu %v", tc.status, tc.path, got, tc.want)
		}
	}

	c = ErrorScoreConfig{
		Enabled:       true,
		DefaultWeight: 2,
		Weights:       map[string]float64{"404": 3, "403": 1, "400": 0},
		Routes: []RouteWeight{
			{Prefix: "/api/", Factor: 0.5},
			{Prefix: "/api/auth", Factor: 4},
			{Prefix: "/status", Factor: 0},
		},
	}
	over := []struct {
		status int
		path   string
		want   float64
	}{
		{404, "/x", 3}, {403, "/x", 1}, {400, "/x", 0}, {418, "/x", 2}, // surcharges
		{404, "/api/users", 1.5},  // ×0,5
		{404, "/api/auth/x", 12},  // préfixe le plus long : ×4
		{404, "/status", 0},       // route neutralisée
	}
	for _, tc := range over {
		if got := c.points(tc.status, tc.path); got != tc.want {
			t.Errorf("surcharge %d %s : %v, attendu %v", tc.status, tc.path, got, tc.want)
		}
	}
}

func errEngine(t *testing.T, errs ErrorScoreConfig, mode string) (*Engine, *time.Time, *[]banRec) {
	t.Helper()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var bans []banRec
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time) {
		bans = append(bans, banRec{ip, reason})
	})
	e.counters.now = func() time.Time { return now }
	e.UpdateConfig(Config{
		Enabled:        true,
		Mode:           mode,
		ErrorThreshold: 1000, // le compteur historique ne doit pas intervenir
		CustomLists:    CustomListsConfig{Paths: []string{"/wp-admin"}},
		Whitelist:      Whitelist{Paths: []string{"/health"}},
		IPScore:        IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{10 * time.Minute}, Errors: errs},
	})
	return e, &now, &bans
}

func respond(e *Engine, ip, path string, status, n int) {
	for i := 0; i < n; i++ {
		e.RecordResponse(ip, path, status)
	}
}

// Des 404 isolés pèsent peu ; une rafale de 400 mène au ban.
func TestErrorScoreWeightsByCode(t *testing.T) {
	e, _, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "block")
	respond(e, "198.51.100.1", "/a", 404, 19) // 9,5
	if len(*bans) != 0 {
		t.Fatalf("19 × 404 (9,5 points) : ban prématuré %v", *bans)
	}
	respond(e, "198.51.100.1", "/a", 404, 1) // 10
	if len(*bans) != 1 || (*bans)[0].reason != "threat: erreurs 4xx répétées" {
		t.Fatalf("20 × 404 : %v", *bans)
	}
	respond(e, "198.51.100.2", "/a", 400, 10)
	if len(*bans) != 2 {
		t.Fatalf("10 × 400 : %v", *bans)
	}
}

// 401, 403 et 429 ne comptent pas : ni ban, ni score.
func TestErrorScoreIgnores401403429(t *testing.T) {
	e, _, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "block")
	for _, code := range []int{401, 403, 429} {
		respond(e, "198.51.100.1", "/login", code, 500)
	}
	if len(*bans) != 0 || e.IPScore("198.51.100.1") != 0 {
		t.Fatalf("bans=%v score=%v", *bans, e.IPScore("198.51.100.1"))
	}
	// Mais on peut les réintroduire explicitement.
	e2, _, bans2 := errEngine(t, ErrorScoreConfig{Enabled: true, Weights: map[string]float64{"403": 1}}, "block")
	respond(e2, "198.51.100.1", "/", 403, 10)
	if len(*bans2) != 1 {
		t.Fatalf("403 pondéré à 1 : %v", *bans2)
	}
}

// Une route sensible pèse plus, une route bruyante moins.
func TestErrorScoreRouteFactor(t *testing.T) {
	errs := ErrorScoreConfig{Enabled: true, Routes: []RouteWeight{{Prefix: "/login", Factor: 3}, {Prefix: "/api/", Factor: 0.1}}}
	e, _, bans := errEngine(t, errs, "block")
	respond(e, "198.51.100.1", "/login", 400, 4) // 12
	if len(*bans) != 1 {
		t.Fatalf("/login ×3 : %v", *bans)
	}
	respond(e, "198.51.100.2", "/api/x", 400, 50) // 5
	if len(*bans) != 1 {
		t.Fatalf("/api/ ×0,1 : %v", *bans)
	}
}

// Les erreurs et les autres signaux alimentent le même score.
func TestErrorScoreSharesScoreWithSignals(t *testing.T) {
	e, _, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "block")
	ip := "198.51.100.1"
	respond(e, ip, "/a", 400, 8) // 8
	if len(*bans) != 0 {
		t.Fatal("ban prématuré")
	}
	e.Check(httptest.NewRequest("GET", "/wp-admin/x", nil), ip) // +2 → 10
	if len(*bans) != 1 || (*bans)[0].reason != "threat: score cumulé" {
		t.Fatalf("un signal doit achever le score des erreurs : %v", *bans)
	}
}

// Des erreurs espacées s'estompent.
func TestErrorScoreDecays(t *testing.T) {
	e, now, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "block")
	for i := 0; i < 8; i++ {
		respond(e, "198.51.100.1", "/a", 400, 4) // 4 points puis 40 minutes
		*now = now.Add(40 * time.Minute)
	}
	if len(*bans) != 0 {
		t.Fatalf("32 points étalés sur plusieurs heures : %v", *bans)
	}
}

// En mode detect, rien n'est banni ; le score repart de zéro.
func TestErrorScoreDetectMode(t *testing.T) {
	e, _, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "detect")
	respond(e, "198.51.100.1", "/a", 400, 30)
	if len(*bans) != 0 {
		t.Fatalf("detect ne doit pas bannir : %v", *bans)
	}
}

// Les chemins de la liste blanche et les erreurs sans route n'alimentent pas le score.
func TestErrorScoreWhitelistedPath(t *testing.T) {
	e, _, bans := errEngine(t, ErrorScoreConfig{Enabled: true}, "block")
	respond(e, "198.51.100.1", "/health/live", 400, 50)
	if len(*bans) != 0 || e.IPScore("198.51.100.1") != 0 {
		t.Fatalf("chemin en liste blanche : bans=%v score=%v", *bans, e.IPScore("198.51.100.1"))
	}
}

// Sans l'option, le compteur historique error_threshold reste seul en jeu.
func TestErrorScoreOffKeepsLegacyCounter(t *testing.T) {
	var bans []banRec
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time) {
		bans = append(bans, banRec{ip, reason})
	})
	e.UpdateConfig(Config{Enabled: true, Mode: "block", ErrorThreshold: 5, IPScore: IPScoreConfig{Enabled: true}})
	for i := 0; i < 5; i++ {
		e.RecordResponse("198.51.100.1", "/a", 403) // le compteur historique compte tous les 4xx
	}
	if len(bans) != 1 || bans[0].reason != "threat: erreurs 4xx répétées" {
		t.Fatalf("compteur historique : %v", bans)
	}
}

// Le rejeu applique la pondération et la décroissance sur l'horloge des logs.
func TestSimulateErrorScore(t *testing.T) {
	cfg := Config{
		IPScore: IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{10 * time.Minute},
			Errors: ErrorScoreConfig{Enabled: true}},
	}
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var burst, spaced, forbidden []SimEvent
	for i := 0; i < 12; i++ {
		burst = append(burst, SimEvent{Time: start.Add(time.Duration(i) * time.Second), IP: "198.51.100.1", Path: "/a", Status: 400})
		spaced = append(spaced, SimEvent{Time: start.Add(time.Duration(i) * 30 * time.Minute), IP: "198.51.100.2", Path: "/a", Status: 400})
		forbidden = append(forbidden, SimEvent{Time: start.Add(time.Duration(i) * time.Second), IP: "198.51.100.3", Path: "/a", Status: 403})
	}
	if got := Simulate(cfg, burst); len(got.Bans) != 1 {
		t.Fatalf("rafale de 400 : %d ban(s)", len(got.Bans))
	}
	if got := Simulate(cfg, spaced); len(got.Bans) != 0 {
		t.Fatalf("400 espacés : %d ban(s)", len(got.Bans))
	}
	if got := Simulate(cfg, forbidden); len(got.Bans) != 0 {
		t.Fatalf("403 : %d ban(s), hors score", len(got.Bans))
	}
}
