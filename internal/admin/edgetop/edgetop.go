// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package edgetop calcule, pour l'Admin, le classement exact des valeurs d'un champ de logs réparties sur plusieurs
// passerelles (ADR 0012). Additionner les « meilleurs N » de chacune donnerait un classement faux : une valeur
// moyenne partout peut dominer le total sans figurer dans aucun top. On applique l'algorithme de seuil (TPUT, Cao et
// Wang 2004) :
//
//  1. chaque passerelle rend ses K meilleures valeurs ; la somme partielle du K-ième rang, τ1, minore le vrai K-ième
//     total ;
//  2. toute valeur du vrai top K a, sur une passerelle au moins, un compte ≥ τ1/m (m passerelles) : chacune rend
//     toutes ses valeurs au-dessus de ce seuil T, ce qui borne par le haut le total des valeurs encore incomplètes ;
//  3. on écarte celles dont la borne haute n'atteint pas le K-ième rang, et l'on demande aux passerelles les comptes
//     exacts des candidats qui leur manquent.
//
// Le résultat est le classement de l'ensemble des lignes, avec ses comptes exacts, au prix de deux ou trois requêtes
// courtes par passerelle. Une passerelle qui répond avec un résultat partiel (délai écoulé) ou qui ne répond pas est
// signalée : le classement porte alors sur ce qui a répondu.
package edgetop

import (
	"context"
	"sort"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/ipsketch"
)

// Caller interroge la passerelle n° node (0 ≤ node < nombre de passerelles).
type Caller func(ctx context.Context, node int, req logapi.TopRequest) (*logapi.TopResponse, error)

// Request décrit le classement voulu.
type Request struct {
	Dim string
	K   int
	// WithIPs : joint à chaque valeur du classement le nombre d'IP attribuables distinctes.
	WithIPs bool
}

// Item est une valeur du classement avec ses comptes, additionnés sur toutes les passerelles.
type Item struct {
	logapi.TopItem
	// UniqueIPs : IP attribuables distinctes de la valeur, si Request.WithIPs ; UniqueExact dit si le compte est exact.
	UniqueIPs   int64
	UniqueExact bool
}

// Result est le classement. Partial : une passerelle n'a pas fini sa lecture, le classement peut être inexact.
// Failed liste les passerelles qui n'ont pas répondu (leurs lignes ne sont pas dans le classement).
type Result struct {
	Items   []Item
	Partial bool
	Failed  map[int]error
}

const roundTrip = 5000 // valeurs par demande de comptes exacts (MaxTopValues d'une passerelle)

// Top rend les K premières valeurs de req.Dim sur les nodes passerelles.
func Top(ctx context.Context, nodes int, call Caller, req Request) Result {
	if req.K <= 0 {
		req.K = 20
	}
	res := Result{Failed: map[int]error{}}
	active := make([]int, 0, nodes)
	for i := 0; i < nodes; i++ {
		active = append(active, i)
	}
	// Une passerelle qui tombe en cours de route fausse les seuils déjà calculés : on recommence sans elle.
	for len(active) > 0 {
		items, partial, failed, err := run(ctx, active, call, req)
		if failed < 0 {
			res.Items, res.Partial = items, partial
			return res
		}
		res.Failed[failed] = err
		next := active[:0:0]
		for _, n := range active {
			if n != failed {
				next = append(next, n)
			}
		}
		active = next
		if ctx.Err() != nil {
			break
		}
	}
	return res
}

// run exécute l'algorithme sur les passerelles actives. failed ≥ 0 : cette passerelle a échoué.
func run(ctx context.Context, active []int, call Caller, req Request) (items []Item, partial bool, failed int, ferr error) {
	m := len(active)
	known := make([]map[string]logapi.TopItem, m) // known[i] : ce que la passerelle active[i] a rendu
	complete := make([]bool, m)
	for i := range known {
		known[i] = map[string]logapi.TopItem{}
	}

	// do envoie à chaque passerelle de la liste sa demande et range les réponses.
	do := func(idx []int, mk func(i int) (logapi.TopRequest, bool), onResp func(i int, r *logapi.TopResponse)) (int, error) {
		type out struct {
			resp *logapi.TopResponse
			err  error
			ran  bool
		}
		outs := make([]out, m)
		var wg sync.WaitGroup
		for _, i := range idx {
			rq, ok := mk(i)
			if !ok {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := call(ctx, active[i], rq)
				outs[i] = out{resp: r, err: err, ran: true}
			}()
		}
		wg.Wait()
		for _, i := range idx {
			if outs[i].ran && outs[i].err != nil {
				return active[i], outs[i].err
			}
		}
		for _, i := range idx {
			if outs[i].ran {
				if outs[i].resp.Partial {
					partial = true
				}
				onResp(i, outs[i].resp)
			}
		}
		return -1, nil
	}
	all := make([]int, m)
	for i := range all {
		all[i] = i
	}
	absorb := func(i int, r *logapi.TopResponse) {
		for _, it := range r.Items {
			known[i][it.Value] = it
		}
	}

	// Tour 1 : les K meilleures de chaque passerelle.
	if f, err := do(all, func(int) (logapi.TopRequest, bool) {
		return logapi.TopRequest{Dim: req.Dim, Mode: "best", K: req.K}, true
	}, func(i int, r *logapi.TopResponse) {
		absorb(i, r)
		complete[i] = r.Complete
	}); f >= 0 {
		return nil, false, f, err
	}

	var open []int // passerelles dont on ne connaît pas toutes les valeurs
	for i := range active {
		if !complete[i] {
			open = append(open, i)
		}
	}

	if len(open) > 0 {
		lower := lowerBounds(known)
		tau1 := kth(lower, req.K)
		t := (tau1 + int64(m) - 1) / int64(m)
		if t < 1 {
			t = 1
		}
		// Tour 2 : tout ce qui atteint le seuil.
		if f, err := do(open, func(int) (logapi.TopRequest, bool) {
			return logapi.TopRequest{Dim: req.Dim, Mode: "above", Min: t}, true
		}, absorb); f >= 0 {
			return nil, false, f, err
		}
		lower = lowerBounds(known)
		tau2 := kth(lower, req.K)

		// Les candidats : ceux dont le total possible atteint le K-ième rang.
		var candidates []string
		for v, lb := range lower {
			missing := int64(0)
			for _, i := range open {
				if _, ok := known[i][v]; !ok {
					missing++
				}
			}
			if lb+missing*(t-1) >= tau2 {
				candidates = append(candidates, v)
			}
		}
		// Tour 3 : les comptes exacts qui manquent.
		for start := 0; ; start += roundTrip {
			if start >= len(candidates) {
				break
			}
			chunk := candidates[start:min(start+roundTrip, len(candidates))]
			if f, err := do(open, func(i int) (logapi.TopRequest, bool) {
				var need []string
				for _, v := range chunk {
					if _, ok := known[i][v]; !ok {
						need = append(need, v)
					}
				}
				return logapi.TopRequest{Dim: req.Dim, Mode: "exact", Values: need}, len(need) > 0
			}, absorb); f >= 0 {
				return nil, false, f, err
			}
		}
		// Une valeur que la passerelle n'a pas vue pèse zéro chez elle.
		// (elle ne figure pas dans known : le total la compte pour 0)
		keep := map[string]bool{}
		for _, v := range candidates {
			keep[v] = true
		}
		for i := range known {
			for v := range known[i] {
				if !keep[v] {
					delete(known[i], v)
				}
			}
		}
	}

	totals := map[string]*logapi.TopItem{}
	for i := range known {
		for v, it := range known[i] {
			tot := totals[v]
			if tot == nil {
				c := it
				c.IPs = nil
				totals[v] = &c
				continue
			}
			tot.Requests += it.Requests
			tot.Errors += it.Errors
			tot.Bytes += it.Bytes
			tot.LatencySum += it.LatencySum
			tot.Flagged += it.Flagged
			tot.Blocked += it.Blocked
			tot.Ok += it.Ok
			tot.Bots += it.Bots
			if it.FirstSeen != "" && (tot.FirstSeen == "" || it.FirstSeen < tot.FirstSeen) {
				tot.FirstSeen = it.FirstSeen
			}
			if it.LastSeen > tot.LastSeen {
				tot.LastSeen = it.LastSeen
			}
			tot.Truncated = tot.Truncated || it.Truncated
			if it.JA3 > tot.JA3 {
				tot.JA3 = it.JA3
			}
		}
	}
	ranked := make([]logapi.TopItem, 0, len(totals))
	for _, t := range totals {
		ranked = append(ranked, *t)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Requests != ranked[j].Requests {
			return ranked[i].Requests > ranked[j].Requests
		}
		return ranked[i].Value < ranked[j].Value
	})
	if len(ranked) > req.K {
		ranked = ranked[:req.K]
	}
	items = make([]Item, len(ranked))
	for i, r := range ranked {
		items[i] = Item{TopItem: r}
	}

	// Tour 4 (facultatif) : les IP attribuables de chaque valeur retenue, à toutes les passerelles.
	if req.WithIPs && len(items) > 0 {
		values := make([]string, len(items))
		for i, it := range items {
			values[i] = it.Value
		}
		sets := map[string]*ipsketch.Set{}
		var mu sync.Mutex
		var bad error
		if f, err := do(all, func(int) (logapi.TopRequest, bool) {
			return logapi.TopRequest{Dim: req.Dim, Mode: "exact", Values: values, WithIPs: true}, true
		}, func(_ int, r *logapi.TopResponse) {
			mu.Lock()
			defer mu.Unlock()
			for _, it := range r.Items {
				if it.IPs == nil {
					continue
				}
				if sets[it.Value] == nil {
					sets[it.Value] = ipsketch.New()
				}
				if err := sets[it.Value].Merge(*it.IPs); err != nil {
					bad = err
				}
			}
		}); f >= 0 {
			return nil, false, f, err
		} else if bad != nil {
			partial = true
		}
		for i := range items {
			if set := sets[items[i].Value]; set != nil {
				items[i].UniqueIPs, items[i].UniqueExact = set.Count(), set.Exact()
			} else {
				items[i].UniqueExact = true
			}
		}
	}
	return items, partial, -1, nil
}

// lowerBounds additionne, par valeur, ce que chaque passerelle en a rendu : un minorant du vrai total.
func lowerBounds(known []map[string]logapi.TopItem) map[string]int64 {
	lb := map[string]int64{}
	for _, k := range known {
		for v, it := range k {
			lb[v] += it.Requests
		}
	}
	return lb
}

// kth rend le k-ième plus grand des totaux (0 s'il y en a moins).
func kth(totals map[string]int64, k int) int64 {
	if len(totals) < k {
		return 0
	}
	all := make([]int64, 0, len(totals))
	for _, n := range totals {
		all = append(all, n)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] > all[j] })
	return all[k-1]
}

// UniqueResult est l'union des ensembles d'IP des passerelles : chaque IP compte une fois, quel que soit le nombre de
// passerelles qui l'ont vue. Le compte est exact tant que l'union tient dans ipsketch.ExactLimit adresses.
type UniqueResult struct {
	Count   int64
	Exact   bool
	Partial bool
	Failed  map[int]error
}

// Unique interroge toutes les passerelles et fusionne leurs résumés.
func Unique(ctx context.Context, nodes int, call func(ctx context.Context, node int) (*logapi.UniqueIPsResponse, error)) UniqueResult {
	resps := make([]*logapi.UniqueIPsResponse, nodes)
	errs := make([]error, nodes)
	var wg sync.WaitGroup
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resps[i], errs[i] = call(ctx, i)
		}()
	}
	wg.Wait()
	res := UniqueResult{Failed: map[int]error{}}
	set := ipsketch.New()
	for i := 0; i < nodes; i++ {
		if errs[i] != nil {
			res.Failed[i] = errs[i]
			continue
		}
		if resps[i].Partial {
			res.Partial = true
		}
		if err := set.Merge(resps[i].IPs); err != nil {
			res.Failed[i] = err
		}
	}
	res.Count, res.Exact = set.Count(), set.Exact()
	return res
}
