// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestStateScoreSurvivesRestartWithDecay(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}})
	for i := 0; i < 4; i++ { // 4 × 2 = 8 points
		hit(e, "198.51.100.1")
	}
	raw, err := json.Marshal(e.SnapshotState())
	if err != nil {
		t.Fatal(err)
	}

	// Redémarrage : un moteur neuf relit l'état une heure plus tard, soit une demi-vie.
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	e2, now2, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}})
	*now2 = now.Add(time.Hour)
	e2.RestoreState(st)
	if got := e2.IPScore("198.51.100.1"); math.Abs(got-4) > 0.01 {
		t.Fatalf("score restauré = %v, attendu 4 (8 points, une demi-vie écoulée)", got)
	}
}

func TestStateExpiredEntriesAreDropped(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Minute}})
	hit(e, "198.51.100.1")
	e.counters.errorExceeded("198.51.100.2", 100, time.Minute)
	e.counters.rateTriggerExceeded("198.51.100.3", 100, time.Minute)
	st := e.SnapshotState()
	if len(st.Scores) != 1 || len(st.Errors) != 1 || len(st.RateTriggers) != 1 {
		t.Fatalf("état = %+v", st)
	}

	e2, now2, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Minute}})
	*now2 = now.Add(2 * time.Hour)
	e2.RestoreState(st)
	if n := e2.counters.size(); n != 0 {
		t.Fatalf("%d entrées périmées restaurées", n)
	}
}

func TestStateErrorWindowKeepsCounting(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{})
	for i := 0; i < 4; i++ {
		e.counters.errorExceeded("198.51.100.2", 5, time.Minute)
	}
	st := e.SnapshotState()

	e2, now2, _ := scoreEngine(t, IPScoreConfig{})
	*now2 = now.Add(10 * time.Second)
	e2.RestoreState(st)
	if !e2.counters.errorExceeded("198.51.100.2", 5, time.Minute) {
		t.Fatal("la cinquième erreur après redémarrage doit atteindre le seuil")
	}
}

func TestStateDoesNotOverwriteLiveCounters(t *testing.T) {
	e, _, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}})
	hit(e, "198.51.100.1")
	st := e.SnapshotState()

	e2, _, _ := scoreEngine(t, IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}})
	for i := 0; i < 3; i++ {
		hit(e2, "198.51.100.1")
	}
	live := e2.IPScore("198.51.100.1")
	e2.RestoreState(st)
	if got := e2.IPScore("198.51.100.1"); got != live {
		t.Fatalf("score = %v, l'état relu a écrasé le score courant %v", got, live)
	}
}

func TestStateIgnoresFutureEventsAndHonoursPerKeyCap(t *testing.T) {
	e, now, _ := scoreEngine(t, IPScoreConfig{})
	ws := WindowState{Window: time.Minute}
	for i := 0; i < maxEventsPerKey+50; i++ {
		ws.Events = append(ws.Events, now.Add(-time.Duration(i)*time.Millisecond))
	}
	ws.Events = append(ws.Events, now.Add(time.Hour)) // horloge réglée en avance au moment de la sauvegarde
	e.RestoreState(State{Errors: map[string]WindowState{"198.51.100.2": ws}})

	sh := e.counters.shard("198.51.100.2")
	if got := len(sh.errors["198.51.100.2"].events); got != maxEventsPerKey {
		t.Fatalf("%d événements restaurés, attendu %d", got, maxEventsPerKey)
	}
}
