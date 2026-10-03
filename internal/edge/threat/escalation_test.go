// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestEscalatedDuration(t *testing.T) {
	c := EscalationConfig{Factor: 2, MaxDuration: Duration{30 * 24 * time.Hour}}
	day := 24 * time.Hour
	cases := []struct {
		prior int
		want  time.Duration
	}{
		{0, day}, {1, 2 * day}, {2, 4 * day}, {3, 8 * day}, {4, 16 * day}, {5, 30 * day}, {50, 30 * day},
	}
	for _, tc := range cases {
		if got := escalatedDuration(day, tc.prior, c); got != tc.want {
			t.Errorf("prior=%d : %v, attendu %v", tc.prior, got, tc.want)
		}
	}
	// Un plafond inférieur à la durée de base ne raccourcit pas les bans.
	if got := escalatedDuration(10*day, 2, EscalationConfig{Factor: 2, MaxDuration: Duration{day}}); got != 10*day {
		t.Errorf("plafond < base : %v", got)
	}
}

func TestEscalationDefaults(t *testing.T) {
	c := Config{Escalation: EscalationConfig{Enabled: true, Window: Duration{90 * 24 * time.Hour}}}
	c.defaults()
	if c.Escalation.Factor != 2 || c.Escalation.MaxDuration.Duration != 30*24*time.Hour {
		t.Fatalf("défauts : %+v", c.Escalation)
	}
	if c.Escalation.Window.Duration != 30*24*time.Hour {
		t.Fatalf("fenêtre non bornée à la rétention de l'historique : %v", c.Escalation.Window.Duration)
	}
}

func escalationEngine(prior func(string, time.Time) int, esc EscalationConfig) (*Engine, *[]time.Time) {
	var expiries []time.Time
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(_, _ string, exp time.Time) { expiries = append(expiries, exp) })
	e.counters.now = func() time.Time { return now }
	e.SetPriorBansFunc(prior)
	e.UpdateConfig(Config{Enabled: true, Mode: "block", BanDuration: Duration{time.Hour}, Escalation: esc})
	return e, &expiries
}

// Un récidiviste est banni plus longtemps ; sans récidive ou option désactivée, la durée de base s'applique.
func TestBanExpiryGrowsWithPriorBans(t *testing.T) {
	var asked []time.Time
	prior := func(_ string, since time.Time) int { asked = append(asked, since); return 2 }
	e, _ := escalationEngine(prior, EscalationConfig{Enabled: true})
	cfg := e.cfg
	now := e.counters.now()

	if got := e.banExpiry("198.51.100.1", cfg).Sub(now); got != 4*time.Hour {
		t.Fatalf("2 bans précédents : %v, attendu 4h", got)
	}
	if len(asked) != 1 || now.Sub(asked[0]) != 7*24*time.Hour {
		t.Fatalf("fenêtre de comptage : %v", asked)
	}

	cfg.Escalation.Enabled = false
	if got := e.banExpiry("198.51.100.1", cfg).Sub(now); got != time.Hour {
		t.Fatalf("option désactivée : %v, attendu 1h", got)
	}
	e2, _ := escalationEngine(func(string, time.Time) int { return 0 }, EscalationConfig{Enabled: true})
	if got := e2.banExpiry("198.51.100.1", e2.cfg).Sub(e2.counters.now()); got != time.Hour {
		t.Fatalf("première infraction : %v, attendu 1h", got)
	}
	e3, _ := escalationEngine(nil, EscalationConfig{Enabled: true})
	if got := e3.banExpiry("198.51.100.1", e3.cfg).Sub(e3.counters.now()); got != time.Hour {
		t.Fatalf("sans historique disponible : %v, attendu 1h", got)
	}
}

// Dans le rejeu, un récidiviste reste banni plus longtemps : une requête qui passerait avec la
// durée de base est encore bloquée par le ban.
func TestSimulateGraduatedBans(t *testing.T) {
	cfg := Config{
		BanDuration: Duration{time.Hour},
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
	}
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ev := func(after time.Duration) SimEvent {
		return SimEvent{Time: start.Add(after), IP: "198.51.100.1", Path: "/wp-admin/x", Status: 404}
	}
	// Ban à 0 (1 h), à 2 h (2 h, car 1 ban précédent), puis une requête à 3 h30 :
	// bloquée par le ban si la durée a doublé, nouveau ban sinon.
	events := []SimEvent{ev(0), ev(2 * time.Hour), ev(3*time.Hour + 30*time.Minute)}

	plain := Simulate(cfg, events)
	if len(plain.Bans) != 3 || plain.BlockedByBan != 0 {
		t.Fatalf("sans bans graduels : %d bans, %d bloquées par ban", len(plain.Bans), plain.BlockedByBan)
	}
	cfg.Escalation = EscalationConfig{Enabled: true}
	grad := Simulate(cfg, events)
	if len(grad.Bans) != 2 || grad.BlockedByBan != 1 {
		t.Fatalf("bans graduels : %d bans, %d bloquées par ban, attendu 2 et 1", len(grad.Bans), grad.BlockedByBan)
	}
}
