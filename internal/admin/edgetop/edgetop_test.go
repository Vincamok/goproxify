// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgetop

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/ipsketch"
)

// fakeNode répond comme la base d'une passerelle : mêmes trois modes, même ordre (compte décroissant, valeur croissante).
type fakeNode struct {
	counts map[string]int64
	ips    map[string][]string
	calls  []string
	mu     sync.Mutex
	fail   error
}

func (f *fakeNode) item(v string) logapi.TopItem {
	n := f.counts[v]
	return logapi.TopItem{Value: v, Requests: n, Errors: n, Bytes: n * 10, LatencySum: n * 3}
}

func (f *fakeNode) answer(req logapi.TopRequest) (*logapi.TopResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.Mode)
	f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	all := make([]logapi.TopItem, 0, len(f.counts))
	for v := range f.counts {
		all = append(all, f.item(v))
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Requests != all[j].Requests {
			return all[i].Requests > all[j].Requests
		}
		return all[i].Value < all[j].Value
	})
	resp := &logapi.TopResponse{}
	switch req.Mode {
	case "best":
		resp.Complete = len(all) <= req.K
		resp.Items = all[:min(len(all), req.K)]
	case "above":
		for _, it := range all {
			if it.Requests >= req.Min {
				resp.Items = append(resp.Items, it)
			}
		}
	case "exact":
		for _, v := range req.Values {
			if _, ok := f.counts[v]; ok {
				it := f.item(v)
				if req.WithIPs {
					set := ipsketch.New()
					for _, ip := range f.ips[v] {
						set.Add(ip)
					}
					sum := set.Summary()
					it.IPs = &sum
				}
				resp.Items = append(resp.Items, it)
			}
		}
	}
	return resp, nil
}

func caller(nodes []*fakeNode) Caller {
	return func(_ context.Context, n int, req logapi.TopRequest) (*logapi.TopResponse, error) {
		return nodes[n].answer(req)
	}
}

func brute(nodes []*fakeNode, k int) []logapi.TopItem {
	sum := map[string]int64{}
	for _, n := range nodes {
		for v, c := range n.counts {
			sum[v] += c
		}
	}
	out := make([]logapi.TopItem, 0, len(sum))
	for v, c := range sum {
		out = append(out, logapi.TopItem{Value: v, Requests: c, Errors: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// randomNodes : des passerelles aux distributions qui ne se ressemblent pas, avec beaucoup d'égalités.
func randomNodes(r *rand.Rand, m, universe int) []*fakeNode {
	nodes := make([]*fakeNode, m)
	for i := range nodes {
		n := &fakeNode{counts: map[string]int64{}}
		skew := 0.5 + r.Float64()*2
		size := 1 + r.Intn(universe)
		for j := 0; j < size; j++ {
			v := fmt.Sprintf("v%03d", r.Intn(universe))
			c := int64(1 + r.ExpFloat64()*skew*float64(universe)/float64(1+r.Intn(universe)))
			if r.Intn(4) == 0 {
				c = int64(1 + r.Intn(5)) // des égalités
			}
			n.counts[v] += c
		}
		nodes[i] = n
	}
	return nodes
}

// Le classement et les comptes sont ceux de l'ensemble des lignes, jamais ceux d'une somme de tops partiels.
func TestTopIsExactOverRandomDistributions(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for trial := 0; trial < 600; trial++ {
		m := 1 + r.Intn(6)
		nodes := randomNodes(r, m, 5+r.Intn(120))
		k := 1 + r.Intn(15)
		res := Top(context.Background(), m, caller(nodes), Request{Dim: "path", K: k})
		if len(res.Failed) != 0 || res.Partial {
			t.Fatalf("essai %d : échec inattendu %v", trial, res.Failed)
		}
		want := brute(nodes, k)
		if len(res.Items) != len(want) {
			t.Fatalf("essai %d (m=%d k=%d) : %d valeurs, attendu %d", trial, m, k, len(res.Items), len(want))
		}
		for i := range want {
			g := res.Items[i]
			if g.Value != want[i].Value || g.Requests != want[i].Requests || g.Errors != want[i].Errors {
				t.Fatalf("essai %d (m=%d k=%d) rang %d : %s=%d, attendu %s=%d", trial, m, k, i, g.Value, g.Requests, want[i].Value, want[i].Requests)
			}
		}
	}
}

// Le piège classique : une valeur moyenne partout, absente des meilleures de chaque passerelle, gagne au total.
func TestTopFindsAValueThatIsNeverInAnyLocalTop(t *testing.T) {
	var nodes []*fakeNode
	for n := 0; n < 4; n++ {
		f := &fakeNode{counts: map[string]int64{"commun": 60}}
		for j := 0; j < 5; j++ {
			f.counts[fmt.Sprintf("local-%d-%d", n, j)] = int64(100 + j)
		}
		nodes = append(nodes, f)
	}
	res := Top(context.Background(), 4, caller(nodes), Request{Dim: "path", K: 3})
	if len(res.Items) == 0 || res.Items[0].Value != "commun" || res.Items[0].Requests != 240 {
		t.Fatalf("tête du classement = %+v, attendu commun=240", res.Items)
	}
	// Additionner les trois meilleures de chaque passerelle l'aurait oubliée.
	naive := map[string]int64{}
	for _, n := range nodes {
		resp, _ := n.answer(logapi.TopRequest{Mode: "best", K: 3})
		for _, it := range resp.Items {
			naive[it.Value] += it.Requests
		}
	}
	if naive["commun"] != 0 {
		t.Fatal("le scénario ne piège plus la somme naïve")
	}
}

func TestTopNeedsOneRoundWhenGatewaysAreComplete(t *testing.T) {
	nodes := []*fakeNode{{counts: map[string]int64{"a": 3, "b": 2}}, {counts: map[string]int64{"a": 1, "c": 5}}}
	res := Top(context.Background(), 2, caller(nodes), Request{Dim: "path", K: 10})
	if len(res.Items) != 3 || res.Items[0].Value != "c" || res.Items[1].Value != "a" || res.Items[1].Requests != 4 {
		t.Fatalf("classement = %+v", res.Items)
	}
	for i, n := range nodes {
		if len(n.calls) != 1 || n.calls[0] != "best" {
			t.Errorf("passerelle %d : appels %v, un seul tour attendu", i, n.calls)
		}
	}
}

func TestTopNeverNeedsMoreThanThreeRoundsPerGateway(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for trial := 0; trial < 200; trial++ {
		m := 2 + r.Intn(4)
		nodes := randomNodes(r, m, 80)
		Top(context.Background(), m, caller(nodes), Request{Dim: "path", K: 5})
		for i, n := range nodes {
			if len(n.calls) > 3 {
				t.Fatalf("essai %d, passerelle %d : %d appels %v", trial, i, len(n.calls), n.calls)
			}
		}
	}
}

// Une passerelle qui tombe en cours de route est écartée, et le classement porte exactement sur les autres.
func TestTopRestartsWithoutAFailingGateway(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	nodes := randomNodes(r, 4, 60)
	nodes[2].fail = errors.New("hors ligne")
	res := Top(context.Background(), 4, caller(nodes), Request{Dim: "path", K: 5})
	if len(res.Failed) != 1 || res.Failed[2] == nil {
		t.Fatalf("Failed = %v", res.Failed)
	}
	want := brute([]*fakeNode{nodes[0], nodes[1], nodes[3]}, 5)
	for i := range want {
		if res.Items[i].Value != want[i].Value || res.Items[i].Requests != want[i].Requests {
			t.Fatalf("rang %d : %+v, attendu %+v", i, res.Items[i], want[i])
		}
	}
}

func TestTopWithIPsCountsEachIPOnceAcrossGateways(t *testing.T) {
	a := &fakeNode{counts: map[string]int64{"ja4-x": 9}, ips: map[string][]string{"ja4-x": {"1.1.1.1", "2.2.2.2", "3.3.3.3"}}}
	b := &fakeNode{counts: map[string]int64{"ja4-x": 4, "ja4-y": 1}, ips: map[string][]string{"ja4-x": {"3.3.3.3", "4.4.4.4"}, "ja4-y": {"9.9.9.9"}}}
	res := Top(context.Background(), 2, caller([]*fakeNode{a, b}), Request{Dim: "tls_ja4", K: 5, WithIPs: true})
	if len(res.Items) != 2 || res.Items[0].Value != "ja4-x" {
		t.Fatalf("classement = %+v", res.Items)
	}
	if x := res.Items[0]; x.UniqueIPs != 4 || !x.UniqueExact {
		t.Errorf("ja4-x : %d IP (exact=%v), attendu 4 exact", x.UniqueIPs, x.UniqueExact)
	}
	if y := res.Items[1]; y.UniqueIPs != 1 {
		t.Errorf("ja4-y : %d IP, attendu 1", y.UniqueIPs)
	}
}

func TestPartialAnswersAreReported(t *testing.T) {
	call := func(_ context.Context, _ int, req logapi.TopRequest) (*logapi.TopResponse, error) {
		return &logapi.TopResponse{Items: []logapi.TopItem{{Value: "a", Requests: 1}}, Complete: true, Partial: true}, nil
	}
	if res := Top(context.Background(), 2, call, Request{Dim: "path", K: 3}); !res.Partial {
		t.Error("une réponse partielle devrait être signalée")
	}
}

func TestUniqueMergesSummariesWithoutDoubleCounting(t *testing.T) {
	mk := func(from, to int) *logapi.UniqueIPsResponse {
		s := ipsketch.New()
		for i := from; i < to; i++ {
			s.Add(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
		}
		return &logapi.UniqueIPsResponse{IPs: s.Summary()}
	}
	resp := []*logapi.UniqueIPsResponse{mk(0, 1000), mk(500, 1500), nil}
	res := Unique(context.Background(), 3, func(_ context.Context, n int) (*logapi.UniqueIPsResponse, error) {
		if resp[n] == nil {
			return nil, errors.New("hors ligne")
		}
		return resp[n], nil
	})
	if res.Count != 1500 || !res.Exact || len(res.Failed) != 1 {
		t.Fatalf("Count=%d Exact=%v Failed=%v, attendu 1500 exact et une passerelle absente", res.Count, res.Exact, res.Failed)
	}
}
