// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Références apprises (ADR 0011, étape 4) : le débit par IP « normal » d'une route, heure par heure.
//
// Chaque minute écoulée donne un échantillon par route : le 90ᵉ centile des requêtes par IP, parmi les IP sans signal. Les
// échantillons d'une heure du jour se gardent sur un anneau ; la référence est une médiane et un écart absolu médian (MAD),
// qu'un attaquant déplace difficilement. Elle ne devient fiable qu'après assez d'observations, et sa dérive est plafonnée.
const (
	refSamples       = 120            // échantillons gardés par heure du jour (deux heures de minutes)
	refMinCold       = 10             // en dessous, aucun signal : trop peu pour comparer
	refMinSamples    = 30             // au-dessus, la référence de cette heure est fiable...
	refDefaultMinAge = 24 * time.Hour // ... si la route est observée depuis au moins aussi longtemps (cycle d'une journée)
	refSigma         = 6.0            // écarts robustes au-delà de la médiane
	refFloor         = 20             // requêtes par minute et par IP en dessous desquelles aucun écart n'est signalé
	refMaxDrift      = 1.25           // la référence ne monte pas de plus de 25 % par période
	refDriftPeriod   = 24 * time.Hour
	refMaxRoutes     = 500
	refMaxIPsPerMin  = 4096
)

type ipMin struct {
	n        uint16
	excluded bool
}

type hourRef struct {
	samples  []float64
	next     int
	pub      float64 // seuil publié : médiane + refSigma × MAD robuste, après plafonnement de la dérive
	anchor   float64 // valeur publiée au début de la période de dérive
	anchorAt int64
	count    int64 // échantillons reçus au total
	updated  int64
}

type routeRef struct {
	mu     sync.Mutex
	first  int64
	minute int64 // minute en cours (UnixNano / minute)
	ips    map[uint32]*ipMin
	hours  [24]hourRef
}

// References apprend le débit par IP d'une route.
type References struct {
	mu     sync.RWMutex
	routes map[string]*routeRef
	minAge atomic.Int64 // time.Duration ; modifiable à chaud par la configuration d'Ephor
}

func newReferences() *References {
	r := &References{routes: map[string]*routeRef{}}
	r.minAge.Store(int64(refDefaultMinAge))
	return r
}

// SetMinAge fixe l'ancienneté minimale d'une route avant que ses références comptent (défaut 24 h).
func (s *Store) SetReferenceMinAge(d time.Duration) {
	if d <= 0 {
		d = refDefaultMinAge
	}
	s.refs.minAge.Store(int64(d))
}

func (r *References) route(name string) *routeRef {
	r.mu.RLock()
	rt := r.routes[name]
	r.mu.RUnlock()
	if rt != nil {
		return rt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rt = r.routes[name]; rt != nil {
		return rt
	}
	if len(r.routes) >= refMaxRoutes {
		return nil
	}
	rt = &routeRef{ips: map[uint32]*ipMin{}}
	r.routes[name] = rt
	return rt
}

// deviation décrit un écart à la référence : l'IP a dépassé le débit normal de la route à cette heure.
type deviation struct {
	count     int
	threshold float64
	cold      bool
}

// observe compte une requête et dit si l'IP s'écarte du débit normal de la route à cette heure. excluded : l'IP a un signal ;
// elle ne nourrit pas la référence (un attaquant ne peut pas enseigner un « normal » trop haut).
func (r *References) observe(ip string, ev Event, excluded bool) *deviation {
	if ev.Route == "" || ev.At.IsZero() {
		return nil
	}
	rt := r.route(ev.Route)
	if rt == nil {
		return nil
	}
	at := ev.At
	minute := at.UnixNano() / int64(time.Minute)

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.first == 0 {
		rt.first = at.UnixNano()
	}
	if minute > rt.minute {
		if rt.minute != 0 {
			rt.finalize(at)
		}
		rt.minute = minute
		clear(rt.ips)
	} else if minute < rt.minute {
		return nil // événement en retard : la minute est déjà comptée
	}
	h := hashIP(ip)
	e := rt.ips[h]
	if e == nil {
		if len(rt.ips) >= refMaxIPsPerMin {
			return nil
		}
		e = &ipMin{}
		rt.ips[h] = e
	}
	if e.n < math.MaxUint16 {
		e.n++
	}
	if excluded {
		e.excluded = true
	}

	hr := &rt.hours[at.UTC().Hour()]
	if len(hr.samples) < refMinCold || hr.pub <= 0 {
		return nil
	}
	thr := math.Max(hr.pub, refFloor)
	if float64(e.n) < thr {
		return nil
	}
	return &deviation{count: int(e.n), threshold: thr, cold: !r.ready(rt, hr, at)}
}

func hashIP(ip string) uint32 { return h32(ip) }

func (r *References) ready(rt *routeRef, hr *hourRef, now time.Time) bool {
	return hr.count >= refMinSamples && now.UnixNano()-rt.first >= r.minAge.Load()
}

// finalize verse la minute écoulée à la référence de son heure. rt.mu doit être tenu.
func (rt *routeRef) finalize(now time.Time) {
	counts := make([]float64, 0, len(rt.ips))
	for _, e := range rt.ips {
		if !e.excluded {
			counts = append(counts, float64(e.n))
		}
	}
	if len(counts) == 0 {
		return
	}
	sort.Float64s(counts)
	sample := counts[int(0.9*float64(len(counts)-1))]
	at := time.Unix(0, rt.minute*int64(time.Minute)).UTC()
	hr := &rt.hours[at.Hour()]
	if len(hr.samples) < refSamples {
		hr.samples = append(hr.samples, sample)
	} else {
		hr.samples[hr.next] = sample
	}
	hr.next = (hr.next + 1) % refSamples
	hr.count++
	hr.updated = now.UnixNano()
	hr.publish(now)
}

// publish recalcule le seuil publié : médiane + refSigma × MAD robuste, sans monter de plus de refMaxDrift par période.
func (hr *hourRef) publish(now time.Time) {
	if len(hr.samples) < refMinCold {
		return
	}
	med := median(hr.samples)
	dev := make([]float64, len(hr.samples))
	for i, v := range hr.samples {
		dev[i] = math.Abs(v - med)
	}
	mad := median(dev) * 1.4826
	cand := med + refSigma*mad
	if hr.anchor == 0 || now.UnixNano()-hr.anchorAt >= int64(refDriftPeriod) {
		if hr.pub > 0 {
			hr.anchor = hr.pub
		} else {
			hr.anchor = cand
		}
		hr.anchorAt = now.UnixNano()
	}
	if limit := hr.anchor * refMaxDrift; cand > limit {
		cand = limit
	}
	hr.pub = cand
}

func median(v []float64) float64 {
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func (r *References) gc(now time.Time) {
	cutoff := now.Add(-7 * 24 * time.Hour).UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, rt := range r.routes {
		rt.mu.Lock()
		stale := rt.minute*int64(time.Minute) < cutoff
		rt.mu.Unlock()
		if stale {
			delete(r.routes, name)
		}
	}
}

// RefInfo décrit une référence apprise, pour l'afficher à l'administrateur : valeur, date et volume observé.
type RefInfo struct {
	Route     string  `json:"route"`
	Hour      int     `json:"hour"` // heure du jour, UTC
	Median    float64 `json:"median"`
	Threshold float64 `json:"threshold"` // requêtes par minute et par IP au-delà desquelles le signal se déclenche
	Samples   int64   `json:"samples"`   // minutes observées
	Ready     bool    `json:"ready"`
	Since     string  `json:"since,omitempty"`   // début de l'observation de la route (RFC 3339)
	Updated   string  `json:"updated,omitempty"` // dernière mise à jour de cette heure
}

// References liste les références apprises, par route puis par heure.
func (s *Store) References() []RefInfo {
	now := s.now()
	s.refs.mu.RLock()
	defer s.refs.mu.RUnlock()
	var out []RefInfo
	for name, rt := range s.refs.routes {
		rt.mu.Lock()
		for h := range rt.hours {
			hr := &rt.hours[h]
			if hr.count == 0 {
				continue
			}
			info := RefInfo{
				Route: name, Hour: h, Median: round1(median(hr.samples)), Threshold: round1(math.Max(hr.pub, refFloor)),
				Samples: hr.count, Ready: s.refs.ready(rt, hr, now),
				Since: time.Unix(0, rt.first).UTC().Format(time.RFC3339), Updated: time.Unix(0, hr.updated).UTC().Format(time.RFC3339),
			}
			out = append(out, info)
		}
		rt.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].Hour < out[j].Hour
	})
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// RefsState est la forme persistée des références apprises.
type RefsState map[string]RouteRefState

type RouteRefState struct {
	First int64                `json:"first"`
	Hours map[int]HourRefState `json:"hours"`
}

type HourRefState struct {
	Samples  []float64 `json:"samples"`
	Pub      float64   `json:"pub"`
	Anchor   float64   `json:"anchor"`
	AnchorAt int64     `json:"anchor_at"`
	Count    int64     `json:"count"`
	Updated  int64     `json:"updated"`
}

func (r *References) export() RefsState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(RefsState, len(r.routes))
	for name, rt := range r.routes {
		rt.mu.Lock()
		st := RouteRefState{First: rt.first, Hours: map[int]HourRefState{}}
		for h := range rt.hours {
			hr := &rt.hours[h]
			if hr.count > 0 {
				st.Hours[h] = HourRefState{Samples: append([]float64(nil), hr.samples...), Pub: hr.pub, Anchor: hr.anchor,
					AnchorAt: hr.anchorAt, Count: hr.count, Updated: hr.updated}
			}
		}
		rt.mu.Unlock()
		if len(st.Hours) > 0 {
			out[name] = st
		}
	}
	return out
}

func (r *References) restore(in RefsState) {
	for name, st := range in {
		rt := r.route(name)
		if rt == nil {
			continue
		}
		rt.mu.Lock()
		if rt.first == 0 {
			rt.first = st.First
		}
		for h, hs := range st.Hours {
			if h < 0 || h > 23 || rt.hours[h].count > 0 {
				continue
			}
			samples := hs.Samples
			if len(samples) > refSamples {
				samples = samples[len(samples)-refSamples:]
			}
			rt.hours[h] = hourRef{samples: append([]float64(nil), samples...), next: len(samples) % refSamples, pub: hs.Pub,
				anchor: hs.Anchor, anchorAt: hs.AnchorAt, count: hs.Count, updated: hs.Updated}
		}
		rt.mu.Unlock()
	}
}
