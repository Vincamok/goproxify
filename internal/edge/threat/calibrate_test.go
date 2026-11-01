// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func calibStart() time.Time { return time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC) }

// calmRoute : 5 req/s depuis 30 adresses sur 20 chemins, pendant d'heures heures (une heure de créneau suffit à le juger avec min_hours 0,1).
func calmRoute(route string, from time.Time, seconds int) []SimEvent {
	var ev []SimEvent
	for s := 0; s < seconds; s++ {
		for i := 0; i < 5; i++ {
			ev = append(ev, SimEvent{Time: from.Add(time.Duration(s)*time.Second + time.Duration(i)*150*time.Millisecond),
				IP: fmt.Sprintf("192.0.2.%d", (s*5+i)%30+1), Path: fmt.Sprintf("/p%d", i%20), Status: 200, Route: route})
		}
	}
	return ev
}

func flood(route string, from time.Time, seconds, rps int) []SimEvent {
	var ev []SimEvent
	for s := 0; s < seconds; s++ {
		for i := 0; i < rps; i++ {
			n := s*rps + i
			ev = append(ev, SimEvent{Time: from.Add(time.Duration(s)*time.Second + time.Duration(i)*time.Second/time.Duration(rps)),
				IP: fmt.Sprintf("10.%d.%d.%d", n/65025, (n/255)%255, n%255+1), Path: "/flood", Status: 200, Route: route})
		}
	}
	return ev
}

func TestCalibrateRecommendsTheMostSensitiveSilentSettingOnACalmWindow(t *testing.T) {
	rep := Calibrate(calmRoute("app.example", calibStart(), 3000), CalibrateOptions{MinHours: 0.1, WindowHours: 168})
	s := rep.Seasonal
	if s.WarmRoutes != 1 || s.Routes != 1 {
		t.Fatalf("la route doit être jugeable : %+v", s)
	}
	if len(s.Candidates) != len(calibFloors)*len(calibFactors)*len(calibSigmas) {
		t.Fatalf("toute la grille est rejouée : %d candidats", len(s.Candidates))
	}
	if s.Recommended == nil || s.Recommended.FloorRPS != 5 || s.Recommended.FastFactor != 5 || s.Recommended.SlowSigmas != 3 {
		t.Fatalf("une période calme laisse le réglage le plus sensible : %+v", s.Recommended)
	}
	if s.Recommended.Warnings+s.Recommended.Probables != 0 {
		t.Fatalf("et il n'aurait rien signalé : %+v", s.Recommended)
	}
}

func TestCalibrateShowsWhatEachSettingWouldHaveRaised(t *testing.T) {
	ev := append(calmRoute("app.example", calibStart(), 3000), flood("app.example", calibStart().Add(3000*time.Second), 120, 400)...)
	s := Calibrate(ev, CalibrateOptions{MinHours: 0.1, WindowHours: 168}).Seasonal
	var sensitive, blunt *CalibSeasonalCandidate
	for i := range s.Candidates {
		c := &s.Candidates[i]
		if c.FloorRPS == 5 && c.FastFactor == 5 && c.SlowSigmas == 3 {
			sensitive = c
		}
		if c.FloorRPS == 50 && c.FastFactor == 20 && c.SlowSigmas == 6 {
			blunt = c
		}
	}
	if sensitive == nil || blunt == nil || sensitive.Probables == 0 || blunt.Probables == 0 {
		t.Fatalf("un flot de 400 req/s sur une route de 5 est vu par tous les réglages : %+v %+v", sensitive, blunt)
	}
	if s.Recommended != nil {
		t.Fatalf("aucun réglage n'est silencieux : pas de recommandation (%+v)", s.Recommended)
	}
	if !strings.Contains(s.Note, "vrais pics") || len(s.Events) == 0 || s.Events[0].Kind != "start" {
		t.Fatalf("le rapport montre ce qui aurait été signalé et dit de l'examiner : %+v", s)
	}
}

func TestCalibrateASmallSpikeSplitsTheGrid(t *testing.T) {
	ev := append(calmRoute("app.example", calibStart(), 3000), flood("app.example", calibStart().Add(3000*time.Second), 120, 30)...)
	s := Calibrate(ev, CalibrateOptions{MinHours: 0.1, WindowHours: 168}).Seasonal
	quiet, loud := 0, 0
	for _, c := range s.Candidates {
		if c.Warnings+c.Probables == 0 {
			quiet++
		} else {
			loud++
		}
	}
	if quiet == 0 || loud == 0 {
		t.Fatalf("un pic modeste doit départager les réglages : %d silencieux, %d bavards", quiet, loud)
	}
}

func TestCalibrateNeedsAWarmRouteToConclude(t *testing.T) {
	s := Calibrate(calmRoute("app.example", calibStart(), 600), CalibrateOptions{MinHours: 2, WindowHours: 1}).Seasonal
	if s.WarmRoutes != 0 || s.Recommended != nil || !strings.Contains(s.Note, "168") {
		t.Fatalf("dix minutes ne jugent aucune route : %+v", s)
	}
	if rep := Calibrate(nil, CalibrateOptions{}); rep.Events != 0 || rep.Seasonal.Note == "" {
		t.Fatalf("aucun accès : %+v", rep)
	}
}

func apiShape(path string) (string, string, bool) {
	const p = "/api/users/"
	if !strings.HasPrefix(path, p) || len(path) == len(p) {
		return "", "", false
	}
	return p + "{int}", path[len(p):], true
}

func walkEvents(ip string, from time.Time, start, n int) []SimEvent {
	var ev []SimEvent
	for i := 0; i < n; i++ {
		ev = append(ev, SimEvent{Time: from.Add(time.Duration(i) * time.Second), IP: ip, Path: fmt.Sprintf("/api/users/%d", start+i), Status: 200, Route: "api.test"})
	}
	return ev
}

func TestCalibrateEnumerationNamesTheWalker(t *testing.T) {
	var ev []SimEvent
	for c := 0; c < 10; c++ {
		ev = append(ev, walkEvents(fmt.Sprintf("198.51.100.%d", c+1), calibStart(), 1, 5)...)
	}
	ev = append(ev, walkEvents("203.0.113.9", calibStart(), 1000, 300)...)
	e := Calibrate(ev, CalibrateOptions{WindowHours: 168, EnumShape: apiShape}).Enumeration
	if e.Recommended == nil || e.Recommended.Floor != 10 {
		t.Fatalf("seul le parcours dépasse le plus petit plancher : %+v", e)
	}
	if len(e.Hits) != 1 || e.Hits[0].IP != "203.0.113.9" || e.Hits[0].Template != "/api/users/{int}" || e.Hits[0].Distinct < 10 {
		t.Fatalf("le rapport nomme qui ce serait : %+v", e.Hits)
	}
}

func TestCalibrateEnumerationRaisesTheFloorWhenClientsReadALot(t *testing.T) {
	var ev []SimEvent
	for c := 0; c < 30; c++ {
		ev = append(ev, walkEvents(fmt.Sprintf("198.51.100.%d", c+1), calibStart(), 1, 40)...)
	}
	e := Calibrate(ev, CalibrateOptions{WindowHours: 168, EnumShape: apiShape}).Enumeration
	if e.Recommended == nil || e.Recommended.Floor < 50 || len(e.Hits) != 0 {
		t.Fatalf("trente clients qui lisent quarante ressources imposent un plancher d'au moins 50, sans personne à signaler : %+v", e)
	}
}

func TestCalibrateWithoutShapeFunctionSkipsEnumeration(t *testing.T) {
	e := Calibrate(calmRoute("a", calibStart(), 100), CalibrateOptions{}).Enumeration
	if e.Note == "" || e.Recommended != nil || e.Candidates == nil || e.Hits == nil {
		t.Fatalf("%+v", e)
	}
}

func TestCalibrateTLSDescribesNonBrowserFingerprints(t *testing.T) {
	var ev []SimEvent
	for i := 0; i < 200; i++ {
		status := 200
		if i%10 != 0 {
			status = 403
		}
		ev = append(ev, SimEvent{Time: calibStart().Add(time.Duration(i) * time.Second), IP: fmt.Sprintf("10.0.0.%d", i%60+1), Path: "/x", Status: status, TLS: "t13d1010h2_aaaaaaaaaaaa_bbbbbbbbbbbb", Route: "a"})
		ev = append(ev, SimEvent{Time: calibStart().Add(time.Duration(i) * time.Second), IP: fmt.Sprintf("10.1.0.%d", i%100+1), Path: "/x", Status: 200, TLS: "t13d1516h2_8daaf6152771_02713d6af862", Route: "a"})
	}
	tl := Calibrate(ev, CalibrateOptions{}).TLS
	if tl.Browsers != 1 || tl.Others != 1 || tl.Shared["50"] != 1 || tl.Shared["100"] != 0 || len(tl.Top) != 1 {
		t.Fatalf("une pile de navigateur et un outil : %+v", tl)
	}
	if top := tl.Top[0]; top.IPs != 60 || top.Requests != 200 || top.ErrorShare < 0.89 || top.ErrorShare > 0.91 {
		t.Fatalf("l'outil échoue presque toujours : %+v", top)
	}
}
