// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/seasonal"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Calibrage des valeurs de départ de l'ADR 0020 (étapes 3 et 4) sur le trafic réel d'une passerelle. Les valeurs livrées sont des points de
// départ ; ce rapport rejoue les accès récents avec une grille de réglages et dit, pour chacun, ce qu'il aurait signalé, puis propose le
// réglage le plus sensible qui n'aurait pas crié au loup sur cette période.
//
// Il suppose que la période rejouée est ordinaire : une vraie attaque dans la fenêtre comptera comme un faux positif. C'est pourquoi le
// rapport montre les alertes du réglage proposé, pour que l'administrateur juge lui-même si ce sont de vrais pics.

// CalibrateOptions règle le calibrage.
type CalibrateOptions struct {
	// MinHours : heures d'observation d'un créneau saisonnier (celles de la config, 2 par défaut).
	MinHours float64
	// WindowHours : durée rejouée, pour ramener le budget d'alertes à la semaine.
	WindowHours float64
	// EnumShape lit les gabarits (surface.EnumShape) ; nil désactive le calibrage de l'énumération.
	EnumShape EnumShapeFunc
	// EnumWindow : fenêtre de l'énumération (10 minutes par défaut).
	EnumWindow time.Duration
}

// CalibSeasonalCandidate est un réglage de la référence saisonnière et ce qu'il aurait signalé.
type CalibSeasonalCandidate struct {
	FloorRPS   float64 `json:"floor_rps"`
	FastFactor float64 `json:"fast_factor"`
	SlowSigmas float64 `json:"slow_sigmas"`
	Warnings   int     `json:"warnings"`
	Probables  int     `json:"probables"`
	// AlertMinutes : durée cumulée des alertes.
	AlertMinutes int `json:"alert_minutes"`
}

// CalibSeasonal est le calibrage de la référence saisonnière.
type CalibSeasonal struct {
	// WarmRoutes et Routes : routes dont un créneau était assez observé pour être jugé, sur toutes celles vues. Sans route jugée, rien n'est conclu.
	WarmRoutes int `json:"warm_routes"`
	Routes     int `json:"routes"`
	// Budget : alertes tolérées sur la fenêtre pour qu'un réglage soit dit silencieux.
	Budget     int                      `json:"budget"`
	Candidates []CalibSeasonalCandidate `json:"candidates"`
	// Recommended : le réglage le plus sensible dans le budget ; nil si aucun, ou si rien n'est jugeable.
	Recommended *CalibSeasonalCandidate `json:"recommended,omitempty"`
	// Events : ce que le réglage proposé (ou, à défaut, le moins sensible) aurait signalé, pour que l'administrateur juge si ce sont de vrais pics.
	Events []seasonal.Event `json:"events"`
	Note   string           `json:"note"`
}

// CalibEnumCandidate est un plancher d'énumération et ce qu'il aurait signalé.
type CalibEnumCandidate struct {
	Floor int `json:"floor"`
	// Flagged : couples (IP, gabarit) qui auraient franchi le seuil.
	Flagged int `json:"flagged"`
}

// CalibEnumHit est un couple (IP, gabarit) signalé par le réglage proposé.
type CalibEnumHit struct {
	IP       string `json:"ip"`
	Route    string `json:"route"`
	Template string `json:"template"`
	Distinct int    `json:"distinct"`
}

// CalibEnumeration est le calibrage de la détection d'énumération. Le profil de surface n'est pas rejoué : le rapport compte ce qui
// franchirait le seuil, la condition « gabarit connu d'un profil convergé » en retranchera.
type CalibEnumeration struct {
	Budget      int                  `json:"budget"`
	Candidates  []CalibEnumCandidate `json:"candidates"`
	Recommended *CalibEnumCandidate  `json:"recommended,omitempty"`
	Hits        []CalibEnumHit       `json:"hits"`
	Note        string               `json:"note"`
}

// CalibTLSFingerprint est une empreinte TLS qui n'est pas celle d'un navigateur connu.
type CalibTLSFingerprint struct {
	JA4        string  `json:"ja4"`
	IPs        int     `json:"ips"`
	Requests   int     `json:"requests"`
	ErrorShare float64 `json:"error_share"`
}

// CalibTLS décrit les empreintes TLS vues : ce que la réputation aurait à juger. La part marquée par le WAF n'est pas dans les logs : le
// rapport ne peut dire que ce que la part d'erreurs laisse entrevoir.
type CalibTLS struct {
	Browsers int `json:"browser_fingerprints"`
	Others   int `json:"other_fingerprints"`
	// Shared : empreintes hors navigateurs partagées par au moins 5, 10, 20, 50, 100 IP.
	Shared map[string]int `json:"shared_by_ips"`
	// Top : les empreintes hors navigateurs partagées par le plus d'IP.
	Top  []CalibTLSFingerprint `json:"top"`
	Note string                `json:"note"`
}

// CalibrationReport est le rapport complet.
type CalibrationReport struct {
	Events      int              `json:"events"`
	FromTime    time.Time        `json:"from,omitempty"`
	ToTime      time.Time        `json:"to,omitempty"`
	Seasonal    CalibSeasonal    `json:"seasonal"`
	Enumeration CalibEnumeration `json:"enumeration"`
	TLS         CalibTLS         `json:"tls"`
}

var (
	calibFloors  = []float64{5, 10, 20, 50}
	calibFactors = []float64{5, 10, 20}
	calibSigmas  = []float64{3, 4, 6}
	calibEnum    = []int{10, 20, 30, 50, 100, 200}
)

// Calibrate rejoue events avec une grille de réglages et rend le rapport.
func Calibrate(events []SimEvent, opt CalibrateOptions) CalibrationReport {
	rep := CalibrationReport{Events: len(events)}
	if len(events) == 0 {
		rep.Seasonal.Note = "aucun accès à rejouer"
		return rep
	}
	ev := append([]SimEvent(nil), events...)
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Time.Before(ev[j].Time) })
	rep.FromTime, rep.ToTime = ev[0].Time, ev[len(ev)-1].Time
	if opt.WindowHours <= 0 {
		opt.WindowHours = math.Max(rep.ToTime.Sub(rep.FromTime).Hours(), 1)
	}
	rep.Seasonal = calibrateSeasonal(ev, opt)
	if opt.EnumShape != nil {
		rep.Enumeration = calibrateEnumeration(ev, opt)
	} else {
		rep.Enumeration.Note = "gabarits de chemin indisponibles : énumération non calibrée"
		rep.Enumeration.Candidates, rep.Enumeration.Hits = []CalibEnumCandidate{}, []CalibEnumHit{}
	}
	rep.TLS = calibrateTLS(ev)
	return rep
}

// weekly ramène un budget par semaine à la durée rejouée, d'au moins une alerte.
func weekly(perWeek int, hours float64) int {
	b := int(math.Round(float64(perWeek) * hours / 168))
	if b < 1 {
		b = 1
	}
	return b
}

// ── Référence saisonnière ────────────────────────────────────────────────────

func replaySeasonal(ev []SimEvent, p seasonal.Params) (cand CalibSeasonalCandidate, warm, routes int, events []seasonal.Event) {
	var cur time.Time
	tr := seasonal.New(func() time.Time { return cur }, func(e seasonal.Event) { events = append(events, e) })
	tr.SetParams(p)
	next := ev[0].Time.Truncate(seasonal.BucketSeconds * time.Second).Add(seasonal.BucketSeconds * time.Second)
	for _, e := range ev {
		cur = e.Time
		for !next.After(cur) {
			tr.Tick(next)
			next = next.Add(seasonal.BucketSeconds * time.Second)
		}
		tr.Record(e.Route, e.IP, e.Status, e.Path)
	}
	cur = ev[len(ev)-1].Time
	tr.Tick(next)
	for _, st := range tr.Status() {
		routes++
		if st.Warm {
			warm++
		}
	}
	for _, e := range events {
		switch {
		case e.Kind == "start" && e.Level == "warning":
			cand.Warnings++
		case (e.Kind == "start" || e.Kind == "escalate") && e.Level == "probable":
			cand.Probables++
		case e.Kind == "end":
			cand.AlertMinutes += int(e.Duration.Minutes())
		}
	}
	for _, a := range tr.Active() {
		cand.AlertMinutes += int(cur.Sub(a.At).Minutes())
	}
	cand.FloorRPS, cand.FastFactor, cand.SlowSigmas = p.FloorRPS, p.FastFactor, p.SlowSigmas
	return cand, warm, routes, events
}

func calibrateSeasonal(ev []SimEvent, opt CalibrateOptions) CalibSeasonal {
	minHours := opt.MinHours
	if minHours <= 0 {
		minHours = 2
	}
	out := CalibSeasonal{Budget: weekly(3, opt.WindowHours), Candidates: []CalibSeasonalCandidate{}, Events: []seasonal.Event{}}
	type run struct {
		c      CalibSeasonalCandidate
		events []seasonal.Event
	}
	var runs []run
	for _, fl := range calibFloors {
		for _, fa := range calibFactors {
			for _, sg := range calibSigmas {
				c, warm, routes, events := replaySeasonal(ev, seasonal.Params{FloorRPS: fl, FastFactor: fa, SlowSigmas: sg, MinSamples: int(minHours * 3600 / seasonal.BucketSeconds)})
				out.WarmRoutes, out.Routes = warm, routes
				runs = append(runs, run{c, events})
			}
		}
	}
	for _, r := range runs {
		out.Candidates = append(out.Candidates, r.c)
	}
	if out.WarmRoutes == 0 {
		out.Note = fmt.Sprintf("aucune route n'a un créneau assez observé (%.0f h par créneau) dans cette fenêtre : prenez 168 h, ou attendez que la référence se remplisse", minHours)
		return out
	}
	// Sensibilité : plus le plancher, le multiple et le nombre d'écarts-types sont bas, plus le réglage est sensible.
	sens := func(c CalibSeasonalCandidate) float64 {
		return -(math.Log(c.FloorRPS) + math.Log(c.FastFactor) + math.Log(c.SlowSigmas))
	}
	best := -1
	for i, r := range runs {
		if r.c.Probables > 0 || r.c.Warnings > out.Budget {
			continue
		}
		if best < 0 || sens(r.c) > sens(runs[best].c) || (sens(r.c) == sens(runs[best].c) && r.c.Warnings < runs[best].c.Warnings) {
			best = i
		}
	}
	shown := runs[0]
	for _, r := range runs {
		if sens(r.c) < sens(shown.c) {
			shown = r
		}
	}
	if best >= 0 {
		c := runs[best].c
		out.Recommended = &c
		shown = runs[best]
		out.Note = fmt.Sprintf("réglage le plus sensible qui n'aurait pas dépassé %d avertissement(s) ni signalé d'attaque probable sur cette période", out.Budget)
	} else {
		out.Note = "même le réglage le moins sensible aurait alerté plus que le budget : la fenêtre contient probablement de vrais pics, ou une route très irrégulière. Examinez les alertes ci-dessous avant de régler quoi que ce soit"
	}
	out.Events = shown.events
	if len(out.Events) > 40 {
		out.Events = out.Events[:40]
	}
	return out
}

// ── Énumération ──────────────────────────────────────────────────────────────

func calibrateEnumeration(ev []SimEvent, opt CalibrateOptions) CalibEnumeration {
	window := opt.EnumWindow
	if window <= 0 {
		window = defaultEnumWindow
	}
	out := CalibEnumeration{Budget: weekly(3, opt.WindowHours), Candidates: []CalibEnumCandidate{}, Hits: []CalibEnumHit{}}
	type hitSet map[string]CalibEnumHit
	byFloor := map[int]hitSet{}
	for _, floor := range calibEnum {
		var cur time.Time
		tr := newEnumTracker(func() time.Time { return cur })
		hits := hitSet{}
		next := ev[0].Time.Add(10 * time.Second)
		for _, e := range ev {
			cur = e.Time
			for !next.After(cur) {
				tr.sweep(window, floor)
				next = next.Add(10 * time.Second)
			}
			tpl, values, ok := opt.EnumShape(e.Path)
			if !ok {
				continue
			}
			key := counterKey(e.IP) + "|" + strings.ToLower(e.Route) + "|" + tpl
			if est, crossed := tr.record(key, values, window, floor); crossed {
				hits[key] = CalibEnumHit{IP: e.IP, Route: e.Route, Template: tpl, Distinct: int(est)}
			}
		}
		byFloor[floor] = hits
		out.Candidates = append(out.Candidates, CalibEnumCandidate{Floor: floor, Flagged: len(hits)})
	}
	for i := range out.Candidates {
		c := out.Candidates[i]
		if c.Flagged <= out.Budget {
			out.Recommended = &c
			break
		}
	}
	shown := byFloor[calibEnum[len(calibEnum)-1]]
	if out.Recommended != nil {
		shown = byFloor[out.Recommended.Floor]
		out.Note = fmt.Sprintf("plus petit plancher qui n'aurait signalé que %d couple(s) IP/gabarit ou moins sur cette période ; la liste montre qui ce serait, pour juger si ce sont de vrais parcours", out.Budget)
	} else {
		out.Note = "même le plus grand plancher aurait signalé plus que le budget : des clients lisent légitimement beaucoup de ressources, ou un parcours a eu lieu. Examinez la liste"
	}
	for _, h := range shown {
		out.Hits = append(out.Hits, h)
	}
	sort.Slice(out.Hits, func(i, j int) bool {
		if out.Hits[i].Distinct != out.Hits[j].Distinct {
			return out.Hits[i].Distinct > out.Hits[j].Distinct
		}
		return out.Hits[i].IP < out.Hits[j].IP
	})
	if len(out.Hits) > 20 {
		out.Hits = out.Hits[:20]
	}
	return out
}

// ── Empreintes TLS ───────────────────────────────────────────────────────────

func calibrateTLS(ev []SimEvent) CalibTLS {
	type agg struct {
		ips      map[string]struct{}
		reqs, er int
	}
	table := behavior.NewTLSTable(nil)
	m := map[string]*agg{}
	out := CalibTLS{Shared: map[string]int{}, Top: []CalibTLSFingerprint{}}
	browsers := map[string]bool{}
	for _, e := range ev {
		if e.TLS == "" {
			continue
		}
		if table.KnownBrowser(e.TLS) {
			browsers[e.TLS] = true
			continue
		}
		a := m[e.TLS]
		if a == nil {
			a = &agg{ips: map[string]struct{}{}}
			m[e.TLS] = a
		}
		a.ips[e.IP] = struct{}{}
		a.reqs++
		if e.Status >= 400 {
			a.er++
		}
	}
	out.Browsers, out.Others = len(browsers), len(m)
	for _, n := range []int{5, 10, 20, 50, 100} {
		out.Shared[strconv.Itoa(n)] = 0
	}
	for ja4, a := range m {
		for _, n := range []int{5, 10, 20, 50, 100} {
			if len(a.ips) >= n {
				out.Shared[strconv.Itoa(n)]++
			}
		}
		out.Top = append(out.Top, CalibTLSFingerprint{JA4: ja4, IPs: len(a.ips), Requests: a.reqs, ErrorShare: round3(float64(a.er) / float64(a.reqs))})
	}
	sort.Slice(out.Top, func(i, j int) bool {
		if out.Top[i].IPs != out.Top[j].IPs {
			return out.Top[i].IPs > out.Top[j].IPs
		}
		return out.Top[i].JA4 < out.Top[j].JA4
	})
	if len(out.Top) > 10 {
		out.Top = out.Top[:10]
	}
	out.Note = "la part de requêtes marquées par le WAF n'est pas dans les logs : la réputation en exige au moins un dixième avant de proposer. Une empreinte hors navigateur partagée par beaucoup d'IP avec peu d'erreurs (application mobile, supervision) ne sera pas proposée ; une qui échoue presque toujours mérite un coup d'œil, même sans proposition"
	return out
}
