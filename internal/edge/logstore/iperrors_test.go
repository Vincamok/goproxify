// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"fmt"
	"testing"
	"time"
)

func errEntry(ts time.Time, ip string, status int) Entry {
	e := access(ts, ip)
	e.Status = status
	return e
}

func TestOnlyClientErrorsFromReadableIPsAreCounted(t *testing.T) {
	s := openTest(t)
	ts := at("2026-10-21T10:00:05Z")
	s.Add(KindAccess, errEntry(ts, "203.0.113.5", 403))
	s.Add(KindAccess, errEntry(ts, "203.0.113.5", 429))
	s.Add(KindAccess, errEntry(ts, "203.0.113.5", 404)) // 404 : ignoré
	s.Add(KindAccess, errEntry(ts, "203.0.113.5", 502)) // erreur de backend : ignorée
	s.Add(KindAccess, errEntry(ts, "203.0.113.5", 200))
	trunc := errEntry(ts, "203.0.113.0", 403)
	trunc.IPTruncated = true // IP tronquée : ne désigne personne
	s.Add(KindAccess, trunc)
	s.Add(KindAccess, errEntry(at("2026-10-21T10:01:00Z"), "2001:DB8::1", 401))
	s.Flush()

	got, err := s.ReadIPErrorsAfter(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"2026-10-21T10:00|203.0.113.5": 2, "2026-10-21T10:01|2001:db8::1": 1}
	if len(got) != len(want) {
		t.Fatalf("%d compteurs, attendu %d : %+v", len(got), len(want), got)
	}
	for _, r := range got {
		if want[r.Minute+"|"+r.IP] != r.Errors {
			t.Errorf("%s %s = %d, attendu %d", r.Minute, r.IP, r.Errors, want[r.Minute+"|"+r.IP])
		}
	}
}

func TestIPErrorCountersResumeAndReturnTheLatestValue(t *testing.T) {
	clock := at("2026-10-21T10:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return clock } })
	for i := 0; i < 3; i++ {
		s.Add(KindAccess, errEntry(at("2026-10-21T10:00:05Z"), fmt.Sprintf("203.0.113.%d", i+1), 403))
	}
	s.Flush()
	first, _ := s.ReadIPErrorsAfter(0, 100)
	if len(first) != 3 {
		t.Fatalf("%d compteurs", len(first))
	}
	pos := first[2].Seq
	if again, _ := s.ReadIPErrorsAfter(pos, 100); len(again) != 0 {
		t.Fatalf("%d compteurs après la dernière position", len(again))
	}
	clock = clock.Add(time.Second)
	s.Add(KindAccess, errEntry(at("2026-10-21T10:00:30Z"), "203.0.113.2", 403))
	s.Flush()
	upd, _ := s.ReadIPErrorsAfter(pos, 100)
	if len(upd) != 1 || upd[0].IP != "203.0.113.2" || upd[0].Errors != 2 {
		t.Fatalf("mise à jour = %+v", upd)
	}
}

// Les compteurs portent des IP : ils sont vidés au bout de 48 h, et effacés avec l'IP sur demande.
func TestIPErrorCountersArePrunedAndErased(t *testing.T) {
	now := at("2026-10-23T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	s.Add(KindAccess, errEntry(at("2026-10-21T09:00:00Z"), "203.0.113.1", 403)) // plus de 48 h
	s.Add(KindAccess, errEntry(at("2026-10-23T11:00:00Z"), "203.0.113.2", 403))
	s.Add(KindAccess, errEntry(at("2026-10-23T11:30:00Z"), "203.0.113.3", 403))
	s.Flush()

	s.Purge(now)
	rows, _ := s.ReadIPErrorsAfter(0, 100)
	if len(rows) != 2 {
		t.Fatalf("%d compteurs après la purge, attendu 2 : %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.IP == "203.0.113.1" {
			t.Fatalf("le compteur de plus de 48 h reste : %+v", r)
		}
	}

	if n, err := s.EraseIP("203.0.113.2"); err != nil || n != 1 {
		t.Fatalf("EraseIP = %d, %v ; attendu 1 ligne (les compteurs ne sont pas des lignes)", n, err)
	}
	rows, _ = s.ReadIPErrorsAfter(0, 100)
	if len(rows) != 1 || rows[0].IP != "203.0.113.3" {
		t.Fatalf("compteurs après effacement = %+v", rows)
	}
	_ = s.Close()
	if grepDir(t, s.opts.Dir, "203.0.113.2") {
		t.Fatal("l'IP effacée reste lisible dans les fichiers (compteur compris)")
	}
}
