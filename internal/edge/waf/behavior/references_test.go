// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"fmt"
	"testing"
	"time"
)

// learn rejoue des minutes de trafic normal sur une route : ips adresses, perMinute requêtes chacune.
func learn(s *Store, clk *clock, route string, minutes, ips, perMinute int) {
	for m := 0; m < minutes; m++ {
		for i := 1; i <= ips; i++ {
			for r := 0; r < perMinute; r++ {
				// Des requêtes espacées de façon irrégulière : ni rafale, ni cadence de script.
				at := clk.t.Add(time.Duration(i*397+r*4793) % time.Minute)
				s.Record(fmt.Sprintf("10.%d.%d.1", i, m%200), Event{At: at, Status: 200, Method: "GET", Path: fmt.Sprintf("/api/%d", (i+r)%5), UA: fmt.Sprintf("ua-%d", i%2), Route: route})
			}
		}
		clk.t = clk.t.Add(time.Minute)
	}
}

func refFor(s *Store, route string, hour int) (RefInfo, bool) {
	for _, r := range s.References() {
		if r.Route == route && r.Hour == hour {
			return r, true
		}
	}
	return RefInfo{}, false
}

func TestReferenceStaysColdUntilEnoughObservations(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetReferenceMinAge(30 * time.Minute)
	learn(s, clk, "api.test", 12, 15, 4)

	// Douze minutes : de quoi comparer (froid), pas de quoi décider.
	spike := func(ip string, n int) Signal {
		var sig []Signal
		for i := 0; i < n; i++ {
			_, sig = s.Record(ip, Event{At: clk.t.Add(time.Duration(i) * 10 * time.Millisecond), Status: 200, Method: "GET", Path: fmt.Sprintf("/api/%d", i%5), UA: "ua-0", Route: "api.test"})
		}
		_ = sig
		got, _ := find(s.Signals(ip), SignalRateDeviation)
		return got
	}
	got := spike("203.0.113.50", 60)
	if got.Name == "" || !got.Detect || !got.Cold {
		t.Fatalf("60 requêtes en une minute contre ~4 de référence, mais 12 minutes seulement : signal froid attendu, reçu %+v", got)
	}
	ref, ok := refFor(s, "api.test", 10)
	if !ok || ref.Ready {
		t.Fatalf("référence prête trop tôt : %+v", ref)
	}
}

func TestReferenceBecomesReliableAndFlagsTheDeviatingIP(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetReferenceMinAge(30 * time.Minute)
	learn(s, clk, "api.test", 45, 15, 4)

	ref, ok := refFor(s, "api.test", 10)
	if !ok || !ref.Ready || ref.Samples < refMinSamples || ref.Median < 3 || ref.Median > 5 {
		t.Fatalf("référence apprise : %+v", ref)
	}
	if ref.Threshold < refFloor || ref.Since == "" || ref.Updated == "" {
		t.Fatalf("la référence doit montrer son seuil, sa date et son volume : %+v", ref)
	}

	// Une IP à 60 requêtes par minute, très au-dessus de la référence, mais sans rafale ni autre signal historique.
	for i := 0; i < 60; i++ {
		s.Record("203.0.113.50", Event{At: clk.t.Add(time.Duration(i) * 900 * time.Millisecond), Status: 200, Method: "GET", Path: fmt.Sprintf("/api/%d", (i*7)%5), UA: "ua-0", Route: "api.test"})
	}
	got, found := find(s.Signals("203.0.113.50"), SignalRateDeviation)
	if !found || got.Cold || !got.Detect {
		t.Fatalf("écart fiable attendu, en detect : %+v", got)
	}
	if score, _ := s.Score("203.0.113.50"); score != 0 {
		t.Fatalf("%s : score=%d", scriptNote, score)
	}
	// Une IP normale ne déclenche rien.
	s.Record("203.0.113.51", Event{At: clk.t, Status: 200, Method: "GET", Path: "/api/1", UA: "ua-0", Route: "api.test"})
	if _, found := find(s.Signals("203.0.113.51"), SignalRateDeviation); found {
		t.Fatal("une IP au débit normal n'est pas en écart")
	}
}

func TestReferenceIgnoresRequestsWithoutARoute(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	learn(s, clk, "", 40, 10, 4)
	if len(s.References()) != 0 {
		t.Fatalf("une requête sans route (hôte inconnu, scanner) ne doit pas créer de référence : %+v", s.References())
	}
}

func TestReferenceCannotBeTaughtByFlaggedIPs(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetReferenceMinAge(30 * time.Minute)
	learn(s, clk, "api.test", 45, 15, 4)
	before, _ := refFor(s, "api.test", 10)

	// Un attaquant arrose la route pendant 40 minutes, depuis des IP qui déclenchent des signaux : elles ne nourrissent pas
	// la référence.
	for m := 0; m < 40; m++ {
		for r := 0; r < 80; r++ { // 80 requêtes dans la minute : rafale (request_burst) dès les premières secondes
			s.Record("198.51.100.77", Event{At: clk.t.Add(time.Duration(r) * 100 * time.Millisecond), Status: 404, Method: "GET", Path: fmt.Sprintf("/x/%d", r), UA: "bot", Route: "api.test"})
		}
		learn(s, clk, "api.test", 1, 15, 4) // le trafic normal continue, et avance l'horloge
	}
	after, _ := refFor(s, "api.test", 10)
	if after.Median > before.Median*1.5 {
		t.Fatalf("médiane passée de %v à %v : l'attaquant a enseigné un « normal » plus haut", before.Median, after.Median)
	}
}

func TestReferenceDriftIsCappedPerPeriod(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetReferenceMinAge(30 * time.Minute)
	learn(s, clk, "api.test", 50, 15, 4) // 10 h 00 – 10 h 49 : débit normal ~4 requêtes par minute et par IP
	pub := func() float64 { return s.refs.routes["api.test"].hours[10].pub }
	start := pub()
	if start <= 0 {
		t.Fatal("la référence doit être publiée")
	}

	// Les jours suivants, le trafic sans aucun signal (IP lentes) triple : un attaquant patient, ou une vraie montée en charge.
	// Dans les deux cas, la référence ne suit pas plus vite que refMaxDrift par période de 24 h.
	for day := 1; day <= 2; day++ {
		clk.t = time.Date(2026, 3, 2+day, 10, 0, 0, 0, time.UTC)
		learn(s, clk, "api.test", 59, 15, 12)
		limit := start
		for d := 0; d < day; d++ {
			limit *= refMaxDrift
		}
		if got := pub(); got > limit+0.01 {
			t.Fatalf("jour %d : seuil publié %v, plafond %v", day, got, limit)
		}
	}
	if pub() <= start {
		t.Fatalf("la référence doit quand même suivre, plus lentement : %v → %v", start, pub())
	}
}

func TestReferencesSurviveARestart(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetReferenceMinAge(30 * time.Minute)
	learn(s, clk, "api.test", 45, 15, 4)
	before, _ := refFor(s, "api.test", 10)

	s2, clk2 := newClockStore(time.Minute)
	clk2.t = clk.t
	s2.SetReferenceMinAge(30 * time.Minute)
	s2.ImportState(s.ExportState())
	after, ok := refFor(s2, "api.test", 10)
	if !ok || after.Samples != before.Samples || after.Median != before.Median || !after.Ready {
		t.Fatalf("avant %+v, après redémarrage %+v", before, after)
	}
}
