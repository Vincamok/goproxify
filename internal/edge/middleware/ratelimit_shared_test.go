// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestRateTracker_SlidingSecond(t *testing.T) {
	var tr rateTracker
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < 50; i++ {
		tr.add(t0.Add(time.Duration(i) * 10 * time.Millisecond)) // 50 requêtes en 500 ms
	}
	if got := tr.rate(t0.Add(500 * time.Millisecond)); got != 50 {
		t.Fatalf("débit sur la seconde : %v, attendu 50", got)
	}
	if got := tr.rate(t0.Add(900 * time.Millisecond)); got != 50 {
		t.Fatalf("à 0,9 s elles comptent encore : %v", got)
	}
	if got := tr.rate(t0.Add(1300 * time.Millisecond)); got <= 0 || got >= 50 {
		t.Fatalf("à 1,3 s les plus anciennes sortent de la fenêtre : %v", got)
	}
	if got := tr.rate(t0.Add(3 * time.Second)); got != 0 {
		t.Fatalf("après 3 s sans requête : %v", got)
	}
}

func TestEffectiveRate(t *testing.T) {
	for _, tc := range []struct{ rps, peers, want float64 }{
		{100, 0, 100}, {100, 60, 40}, {100, 100, 10}, {100, 250, 10}, {10, 4, 6},
	} {
		if got := effectiveRate(tc.rps, tc.peers); got != tc.want {
			t.Errorf("effectiveRate(%v, %v) = %v, attendu %v", tc.rps, tc.peers, got, tc.want)
		}
	}
}

// La part des pairs est retirée du débit de recharge, pas de la rafale : un seau vide se recharge plus lentement.
func TestAllowWithPeers_ScalesTheRefill(t *testing.T) {
	admitted := func(peers float64) int {
		rl := &rateLimiter{tokens: 0, maxTokens: 1000, refillRate: 100, lastRefill: time.Now().Add(-time.Second), lastSeen: time.Now()}
		n := 0
		for i := 0; i < 1000; i++ {
			if ok, _ := rl.allowWithPeers(peers); ok {
				n++
			}
		}
		return n
	}
	alone, shared := admitted(0), admitted(60)
	if alone < 95 || alone > 110 {
		t.Errorf("seul : %d requêtes pour une seconde de recharge à 100/s", alone)
	}
	if shared < 35 || shared > 50 {
		t.Errorf("avec un pair qui admet 60/s : %d requêtes (40 attendues)", shared)
	}
}

func TestRateShare_PeerAnnouncementsExpireAndReplace(t *testing.T) {
	s := &rateShareStore{local: map[string]*rateTracker{}, peers: map[string]map[string]peerRate{}}
	now := time.Unix(2_000_000, 0)
	s.merge("a", []RateEntry{{Key: "k", Rate: 30}, {Key: "autre", Rate: 5}}, now)
	s.merge("b", []RateEntry{{Key: "k", Rate: 20}}, now)
	if got := s.peerRateSum("k", now.Add(100*time.Millisecond)); got != 50 {
		t.Fatalf("somme des pairs : %v", got)
	}
	// Le pair a ne parle plus de k : il est au repos chez lui.
	s.merge("a", []RateEntry{{Key: "autre", Rate: 5}}, now.Add(500*time.Millisecond))
	if got := s.peerRateSum("k", now.Add(600*time.Millisecond)); got != 20 {
		t.Fatalf("après le silence de a : %v", got)
	}
	// Une annonce périmée (pair tombé) est ignorée : le débit local redevient entier.
	if got := s.peerRateSum("k", now.Add(3*time.Second)); got != 0 {
		t.Fatalf("annonce périmée : %v", got)
	}
}

func TestRateShare_ExportOnlyActiveKeys(t *testing.T) {
	s := &rateShareStore{local: map[string]*rateTracker{}, peers: map[string]map[string]peerRate{}}
	now := time.Unix(3_000_000, 0)
	for i := 0; i < 7; i++ {
		s.admitted("k", now)
	}
	if got := s.export(now); len(got) != 1 || got[0].Key != "k" || got[0].Rate != 7 {
		t.Fatalf("export : %+v", got)
	}
	if got := s.export(now.Add(5 * time.Second)); len(got) != 0 {
		t.Fatalf("une clé au repos ne s'annonce pas : %+v", got)
	}
	if !s.active(now.Add(time.Second)) || s.active(now.Add(time.Minute)) {
		t.Error("HasSharedRates : actif juste après une admission, plus après une minute")
	}
}

// Bout en bout dans le middleware : un pair qui admet déjà tout le débit réduit celui de la passerelle à son plancher.
func TestRateLimit_SharedAnnouncementsSlowTheLocalBucket(t *testing.T) {
	cfg := &router.RateLimitConfig{RequestsPerSecond: 100, Burst: 100, Shared: true}
	h := RateLimit(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	send := func(ip string) bool {
		req := httptest.NewRequest(http.MethodGet, "http://partage.test/", nil)
		req.RemoteAddr = ip + ":4000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code == http.StatusOK
	}
	drain := func(ip string) {
		for i := 0; i < 300; i++ {
			send(ip)
		}
	}
	window := func(ip string) int {
		n := 0
		for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
			if send(ip) {
				n++
			}
			time.Sleep(time.Millisecond)
		}
		return n
	}

	const alone, withPeer = "203.0.113.61", "203.0.113.62"
	drain(alone)
	drain(withPeer)
	MergeRates("pair-b", []RateEntry{{Key: "partage.test\x00" + withPeer, Rate: 100}})
	a, b := window(alone), window(withPeer)
	if a < 15 {
		t.Fatalf("sans pair, 300 ms de recharge à 100/s devraient admettre ~30 requêtes : %d", a)
	}
	if b > a/2 {
		t.Errorf("avec un pair à 100/s le débit local doit tomber vers 10 %% : %d contre %d sans pair", b, a)
	}
}
