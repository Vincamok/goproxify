// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"io"
	"log/slog"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

type explained struct {
	ip, reason string
	signals    []router.BanSignal
}

func explainEngine(t *testing.T, cfg Config) (*Engine, *time.Time, *[]explained) {
	t.Helper()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var bans []explained
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time, signals []router.BanSignal) {
		bans = append(bans, explained{ip, reason, signals})
	})
	e.counters.now = func() time.Time { return now }
	cfg.Enabled = true
	cfg.Mode = "block"
	e.UpdateConfig(cfg)
	return e, &now, &bans
}

func sumPoints(signals []router.BanSignal) float64 {
	var t float64
	for _, s := range signals {
		t += s.Points
	}
	return t
}

// Un ban sur score cumulé liste chaque signal avec ses points : leur somme est le score qui a déclenché le ban.
func TestScoreBanExplainsEverySignalAndSumsToTheScore(t *testing.T) {
	e, now, bans := explainEngine(t, Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}, UAs: []string{"sqlmap"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{time.Hour}, Errors: ErrorScoreConfig{Enabled: true}},
	})
	const ip = "198.51.100.1"
	e.Check(httptest.NewRequest("GET", "/wp-admin/setup.php", nil), ip) // 2
	*now = now.Add(10 * time.Minute)
	req := httptest.NewRequest("GET", "/elsewhere", nil)
	req.Header.Set("User-Agent", "sqlmap/1.7") // 3
	e.Check(req, ip)
	*now = now.Add(10 * time.Minute)
	for i := 0; i < 5; i++ { // 5 × 1 (400)
		e.RecordResponse(ip, "/api/x", 400)
	}
	if len(*bans) != 0 {
		t.Fatalf("ban prématuré : %+v", *bans)
	}
	acc := e.IPScore(ip)
	e.RecordResponse(ip, "/api/y", 400)

	if len(*bans) != 1 {
		t.Fatalf("bans : %+v", *bans)
	}
	b := (*bans)[0]
	names := map[string]router.BanSignal{}
	for _, s := range b.signals {
		names[s.Name] = s
	}
	for _, want := range []string{"custom_path", "custom_ua", "error4xx"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("signal %q absent de l'explication : %+v", want, b.signals)
		}
	}
	if names["custom_path"].Value != "/wp-admin/setup.php" || names["custom_ua"].Value != "sqlmap/1.7" || names["error4xx"].Value != "400 /api/y" {
		t.Fatalf("valeurs observées : %+v", b.signals)
	}
	if got := sumPoints(b.signals); math.Abs(got-(acc+1)) > 0.15 {
		t.Fatalf("somme des points = %v, score au ban = %v", got, acc+1)
	}
	for i := 1; i < len(b.signals); i++ {
		if b.signals[i].Points > b.signals[i-1].Points {
			t.Fatalf("signaux à ordonner du plus lourd au plus léger : %+v", b.signals)
		}
	}
	if e.IPScore(ip) != 0 || len(e.counters.scoreBreakdown(ip)) != 0 {
		t.Fatal("le détail du score doit être remis à zéro avec lui")
	}
}

// La décroissance s'applique au détail comme au score : une vieille contribution pèse moins qu'une récente.
func TestScoreBreakdownDecaysWithTheScore(t *testing.T) {
	e, now, _ := explainEngine(t, Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}},
	})
	e.Check(httptest.NewRequest("GET", "/wp-admin/a", nil), "198.51.100.1") // 2 points
	*now = now.Add(time.Hour)
	got := e.counters.scoreBreakdown("198.51.100.1")
	if len(got) != 1 || math.Abs(got[0].Points-1) > 0.05 {
		t.Fatalf("détail après une demi-vie = %+v, attendu 1 point", got)
	}
}

// Un signal d'IP connue interdit bannit tout de suite et l'explique par la liste.
func TestImmediateBanExplainsTheList(t *testing.T) {
	e, _, bans := explainEngine(t, Config{
		CustomLists: CustomListsConfig{IPs: []string{"203.0.113.9"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 100},
	})
	e.Check(httptest.NewRequest("GET", "/", nil), "203.0.113.9")
	if len(*bans) != 1 || len((*bans)[0].signals) != 1 {
		t.Fatalf("bans : %+v", *bans)
	}
	if s := (*bans)[0].signals[0]; s.Name != "custom_ip" || s.Points != 5 || s.Value != "203.0.113.9" {
		t.Fatalf("signal : %+v", s)
	}
}

// Sans score cumulé, les signaux de la requête qui déclenche le ban sont l'explication.
func TestPlainBanExplainsTheRequestSignals(t *testing.T) {
	e, _, bans := explainEngine(t, Config{CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}}})
	e.Check(httptest.NewRequest("GET", "/wp-admin/x", nil), "198.51.100.1")
	if len(*bans) != 1 || (*bans)[0].signals[0].Name != "custom_path" || (*bans)[0].signals[0].Value != "/wp-admin/x" {
		t.Fatalf("bans : %+v", *bans)
	}
}

func TestRateBanExplainsTheThreshold(t *testing.T) {
	e, _, bans := explainEngine(t, Config{RateLimit: 1, RateWindow: Duration{time.Second}, RateBanThreshold: 1})
	for i := 0; i < 5; i++ {
		e.Check(httptest.NewRequest("GET", "/", nil), "198.51.100.1")
	}
	if len(*bans) == 0 {
		t.Fatal("ban rate attendu")
	}
	s := (*bans)[0].signals
	if len(s) != 1 || s[0].Name != "rate" || s[0].Points != 4 || !strings.Contains(s[0].Value, "1 req/s") {
		t.Fatalf("signal : %+v", s)
	}
}

// La valeur vient de la requête : bornée, sans caractère de contrôle.
func TestSignalValueIsBoundedAndSanitised(t *testing.T) {
	got := clipValue("/a\r\nb" + strings.Repeat("é", 500))
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("caractère de contrôle conservé : %q", got)
	}
	if n := len([]rune(got)); n != maxSignalValue+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("valeur non bornée : %d runes", n)
	}
}

// Le détail du score fait partie de l'état conservé au redémarrage : un ban posé après coup l'explique encore.
func TestScoreBreakdownSurvivesRestart(t *testing.T) {
	cfg := Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 9, HalfLife: Duration{time.Hour}},
	}
	e, now, _ := explainEngine(t, cfg)
	for i := 0; i < 4; i++ {
		e.Check(httptest.NewRequest("GET", "/wp-admin/a", nil), "198.51.100.1")
	}
	st := e.SnapshotState()

	e2, now2, bans := explainEngine(t, cfg)
	*now2 = *now
	e2.RestoreState(st)
	e2.Check(httptest.NewRequest("GET", "/wp-admin/b", nil), "198.51.100.1")
	if len(*bans) != 1 {
		t.Fatalf("bans : %+v", *bans)
	}
	s := (*bans)[0].signals
	if len(s) != 1 || s[0].Name != "custom_path" || math.Abs(s[0].Points-10) > 0.1 || s[0].Value != "/wp-admin/b" {
		t.Fatalf("explication après redémarrage : %+v", s)
	}
}
