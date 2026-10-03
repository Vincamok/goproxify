// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"io"
	"log/slog"
	"math"
	"net/http/httptest"
	"testing"
	"time"
)

type banRec struct {
	ip, reason string
}

// scoreEngine : moteur avec horloge pilotée, un chemin sensible (2 points) et le score activé.
func scoreEngine(t *testing.T, score IPScoreConfig) (*Engine, *time.Time, *[]banRec) {
	t.Helper()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var bans []banRec
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time) {
		bans = append(bans, banRec{ip, reason})
	})
	e.counters.now = func() time.Time { return now }
	e.UpdateConfig(Config{
		Enabled:     true,
		Mode:        "block",
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}, IPs: []string{"203.0.113.9"}},
		IPScore:     score,
	})
	return e, &now, &bans
}

func hit(e *Engine, ip string) (blocked bool) {
	blocked, _ = e.Check(httptest.NewRequest("GET", "/wp-admin/setup.php", nil), ip)
	return blocked
}

// Sans score, un signal suffit pour bannir (comportement historique inchangé).
func TestWithoutScoreFirstSignalBans(t *testing.T) {
	e, _, bans := scoreEngine(t, IPScoreConfig{})
	hit(e, "198.51.100.1")
	if len(*bans) != 1 {
		t.Fatalf("bans : %v", *bans)
	}
}

// Avec le score, les requêtes sont bloquées mais l'IP n'est bannie qu'au seuil cumulé.
func TestScoreBansOnlyAtThreshold(t *testing.T) {
	e, _, bans := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 10})
	for i := 0; i < 4; i++ { // 4 × 2 = 8 < 10
		if !hit(e, "198.51.100.1") {
			t.Fatal("la requête doit être bloquée même avant le ban")
		}
	}
	if len(*bans) != 0 {
		t.Fatalf("ban prématuré : %v", *bans)
	}
	hit(e, "198.51.100.1") // 10
	if len(*bans) != 1 || (*bans)[0].reason != "threat: score cumulé" {
		t.Fatalf("ban au seuil attendu : %v", *bans)
	}
	// Le ban remet le score à zéro.
	if got := e.IPScore("198.51.100.1"); got != 0 {
		t.Fatalf("score après ban : %v", got)
	}
}

// Des signaux espacés dans le temps s'estompent : pas de ban, alors que sans décroissance il y en aurait un.
func TestScoreDecaysOverTime(t *testing.T) {
	e, now, bans := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{10 * time.Minute}})
	for i := 0; i < 4; i++ { // 8
		hit(e, "198.51.100.1")
	}
	*now = now.Add(30 * time.Minute) // 3 demi-vies : 8 → 1
	if got := e.IPScore("198.51.100.1"); math.Abs(got-1) > 0.01 {
		t.Fatalf("score après 3 demi-vies : %v, attendu 1", got)
	}
	for i := 0; i < 4; i++ { // 1 + 8 = 9
		hit(e, "198.51.100.1")
	}
	if len(*bans) != 0 {
		t.Fatalf("la décroissance aurait dû éviter le ban : %v", *bans)
	}
	hit(e, "198.51.100.1") // 11
	if len(*bans) != 1 {
		t.Fatalf("ban attendu une fois le seuil franchi : %v", *bans)
	}
}

func TestScoreHalfLifeExact(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}})
	hit(e, "198.51.100.1")
	hit(e, "198.51.100.1") // 4
	*now = now.Add(time.Hour)
	if got := e.IPScore("198.51.100.1"); math.Abs(got-2) > 0.001 {
		t.Fatalf("après une demi-vie : %v, attendu 2", got)
	}
}

// Une IP des listes de menaces est bannie immédiatement, même avec le score.
func TestScoreKnownBadIPBansImmediately(t *testing.T) {
	e, _, bans := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100})
	blocked, _ := e.Check(httptest.NewRequest("GET", "/", nil), "203.0.113.9")
	if !blocked || len(*bans) != 1 || (*bans)[0].reason != "threat: custom_ip" {
		t.Fatalf("blocked=%v bans=%v", blocked, *bans)
	}
}

// Le score est propre à chaque IP.
func TestScoreIsPerIP(t *testing.T) {
	e, _, bans := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 10})
	for i := 0; i < 3; i++ {
		hit(e, "198.51.100.1")
		hit(e, "198.51.100.2")
	}
	if len(*bans) != 0 {
		t.Fatalf("6 points par IP : pas de ban : %v", *bans)
	}
}

// Débannir une IP (ResetIP) efface aussi son score.
func TestResetIPClearsScore(t *testing.T) {
	e, _, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100})
	hit(e, "198.51.100.1")
	e.ResetIP("198.51.100.1")
	if got := e.IPScore("198.51.100.1"); got != 0 {
		t.Fatalf("score après ResetIP : %v", got)
	}
}

// Un score tombé quasi à zéro est oublié : pas de croissance mémoire pour les IP passagères.
func TestScoreForgottenWhenDecayed(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Minute}})
	hit(e, "198.51.100.1")
	before := e.counters.size()
	*now = now.Add(time.Hour)
	hit(e, "198.51.100.2") // déclenche le nettoyage du shard concerné
	for i := range e.counters.shards {
		sh := &e.counters.shards[i]
		sh.mu.Lock()
		sh.gcLocked(*now)
		sh.mu.Unlock()
	}
	if after := e.counters.size(); after >= before+1 {
		t.Fatalf("score décru non oublié : %d → %d", before, after)
	}
}

// Le rejeu (Simulate) applique la décroissance sur l'horloge des événements.
func TestSimulateUsesScoreDecay(t *testing.T) {
	cfg := Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{10 * time.Minute}},
	}
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var burst, spaced []SimEvent
	for i := 0; i < 6; i++ {
		burst = append(burst, SimEvent{Time: start.Add(time.Duration(i) * time.Second), IP: "198.51.100.1", Path: "/wp-admin/x", Status: 404})
		spaced = append(spaced, SimEvent{Time: start.Add(time.Duration(i) * 30 * time.Minute), IP: "198.51.100.2", Path: "/wp-admin/x", Status: 404})
	}
	if got := Simulate(cfg, burst); len(got.Bans) != 1 {
		t.Fatalf("série rapprochée : %d ban(s)", len(got.Bans))
	}
	if got := Simulate(cfg, spaced); len(got.Bans) != 0 {
		t.Fatalf("signaux espacés : %d ban(s), attendu 0", len(got.Bans))
	}
}

func TestIPScoreDefaults(t *testing.T) {
	c := Config{IPScore: IPScoreConfig{Enabled: true}}
	c.defaults()
	if c.IPScore.BanThreshold != 10 || c.IPScore.HalfLife.Duration != 10*time.Minute {
		t.Fatalf("défauts : %+v", c.IPScore)
	}
}
