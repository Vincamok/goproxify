// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipsketch

import (
	"fmt"
	"math"
	"testing"
)

func ip(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) }

func TestSmallSetsAreExactAndDeduplicated(t *testing.T) {
	s := New()
	for i := 0; i < 500; i++ {
		s.Add(ip(i % 300))
	}
	s.Add("")
	if !s.Exact() || s.Count() != 300 {
		t.Fatalf("exact=%v count=%d, attendu 300 exact", s.Exact(), s.Count())
	}
}

func TestUnionOfExactSummariesCountsSharedIPsOnce(t *testing.T) {
	a, b := New(), New()
	for i := 0; i < 1000; i++ {
		a.Add(ip(i))
	}
	for i := 500; i < 1500; i++ {
		b.Add(ip(i))
	}
	u := New()
	for _, s := range []Summary{a.Summary(), b.Summary()} {
		if err := u.Merge(s); err != nil {
			t.Fatal(err)
		}
	}
	if !u.Exact() || u.Count() != 1500 {
		t.Fatalf("exact=%v count=%d, attendu 1500", u.Exact(), u.Count())
	}
}

func within(got int64, want int, pct float64) bool {
	return math.Abs(float64(got)-float64(want)) <= float64(want)*pct/100
}

func TestLargeSetsBecomeASketchWithinOnePercent(t *testing.T) {
	for _, n := range []int{ExactLimit + 1, 5000, 50000, 400000} {
		s := New()
		for i := 0; i < n; i++ {
			s.Add(ip(i))
		}
		if s.Exact() {
			t.Fatalf("n=%d : devrait être un sketch", n)
		}
		if got := s.Count(); !within(got, n, 2) {
			t.Errorf("n=%d : estimé %d (écart > 2 %%)", n, got)
		}
	}
}

// L'union d'un résumé exact et d'un sketch qui se recouvrent ne compte pas deux fois les IP communes.
func TestUnionMixingExactAndSketchDoesNotDoubleCount(t *testing.T) {
	big, small := New(), New()
	for i := 0; i < 30000; i++ {
		big.Add(ip(i))
	}
	for i := 20000; i < 21000; i++ {
		small.Add(ip(i)) // tout dans big
	}
	for i := 30000; i < 30500; i++ {
		small.Add(ip(i)) // 500 nouvelles
	}
	for name, order := range map[string][]Summary{
		"sketch puis exact": {big.Summary(), small.Summary()},
		"exact puis sketch": {small.Summary(), big.Summary()},
	} {
		u := New()
		for _, s := range order {
			if err := u.Merge(s); err != nil {
				t.Fatal(err)
			}
		}
		if u.Exact() {
			t.Errorf("%s : devrait être estimé", name)
		}
		if got := u.Count(); !within(got, 30500, 2) {
			t.Errorf("%s : %d, attendu environ 30500", name, got)
		}
	}
}

func TestMergeRejectsACorruptedSketch(t *testing.T) {
	if err := New().Merge(Summary{HLL: "pas-du-base64"}); err == nil {
		t.Error("un résumé illisible devrait être refusé")
	}
	if err := New().Merge(Summary{HLL: "AAAA"}); err == nil {
		t.Error("un sketch de mauvaise taille devrait être refusé")
	}
}
