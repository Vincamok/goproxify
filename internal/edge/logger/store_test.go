// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

func testStore(t *testing.T) (*logstore.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "logs")
	s, err := logstore.Open(logstore.Options{Dir: dir, IPKey: bytes.Repeat([]byte{9}, ipcrypt.KeySize)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// waitRows attend que n lignes du type soient lisibles : l'entrée traverse deux goroutines avant la base.
func waitRows(t *testing.T, s *logstore.Store, kind logstore.Kind, n int) []logstore.Row {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.Flush()
		rows, err := s.ReadAfter(kind, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= n || time.Now().After(deadline) {
			if len(rows) != n {
				t.Fatalf("%d lignes %s, attendu %d", len(rows), kind, n)
			}
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAccessLoggerStoresEachProtectionMode(t *testing.T) {
	cases := []struct {
		name         string
		anon, pseudo bool
		wantIP       string
		wantTrunc    bool
		wantPseudo   bool
		clearInStore bool // l'IP réelle est lisible dans les fichiers
	}{
		{"normal", false, false, "203.0.113.42", false, false, true},
		{"anonymisation", true, false, "203.0.113.0", true, false, false},
		{"pseudonymisation", false, true, "203.0.113.0", true, true, false},
		{"anonymisation l'emporte", true, true, "203.0.113.0", true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, dir := testStore(t)
			al := NewAccessLogger()
			al.SetStore(st)
			al.SetIPProtection(c.anon, c.pseudo)
			h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				_, _ = w.Write([]byte("ok"))
			}))
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com:443/api/ping?x=1", nil)
			req.Host = "app.example.com:443"
			req.RemoteAddr = "203.0.113.42:51234"
			req.Header.Set("User-Agent", "curl/8")
			req.Header.Set("X-Request-ID", "req-7")
			h.ServeHTTP(httptest.NewRecorder(), req)

			r := waitRows(t, st, logstore.KindAccess, 1)[0]
			if r.IP != c.wantIP || r.IPTruncated != c.wantTrunc || r.Pseudonymized != c.wantPseudo {
				t.Errorf("ip=%q tronquée=%v pseudonymisée=%v, attendu %q %v %v", r.IP, r.IPTruncated, r.Pseudonymized, c.wantIP, c.wantTrunc, c.wantPseudo)
			}
			if r.Domain != "app.example.com" || r.Method != "GET" || r.Path != "/api/ping" || r.Status != http.StatusTeapot ||
				r.Bytes != 2 || r.UserAgent != "curl/8" || r.RequestID != "req-7" || r.Level != "warn" || r.Component != "edge" {
				t.Errorf("ligne d'accès incomplète : %+v", r)
			}
			if c.wantPseudo {
				if got, err := st.RevealIP(logstore.KindAccess, r.ID); err != nil || got != "203.0.113.42" {
					t.Errorf("RevealIP = %q, %v", got, err)
				}
			}
			_ = st.Close()
			if clear := countIn(t, dir, "203.0.113.42") > 0; clear != c.clearInStore {
				t.Errorf("IP réelle lisible dans la base = %v, attendu %v", clear, c.clearInStore)
			}
		})
	}
}

func countIn(t *testing.T, dir, needle string) int {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var total int
	for _, de := range entries {
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		total += bytes.Count(b, []byte(needle))
	}
	return total
}

func TestAccessLoggerWithoutStoreStillShips(t *testing.T) {
	al := NewAccessLogger()
	got := make(chan ShipEntry, 1)
	al.SetForwarder(func(batch []ShipEntry) {
		for _, e := range batch {
			select {
			case got <- e:
			default:
			}
		}
	})
	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	req.RemoteAddr = "203.0.113.42:1"
	for range 100 { // le lot part à 100 entrées ou au bout de 5 s
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("sans base locale, les accès doivent quand même être expédiés")
	}
}

func TestSystemLogsGoToTheStoreExceptLocalOnlyLines(t *testing.T) {
	st, _ := testStore(t)
	dl := New("info", "json", "")
	dl.SetNodeName("edge-1")
	dl.SetStore(st)

	dl.Info("backend injoignable", "domain", "app.example.com:443", "code", 502)
	dl.Logger().InfoContext(LocalOnly(context.Background()), "ligne d'accès texte")
	dl.Logger().Debug("trop bavard")

	rows := waitRows(t, st, logstore.KindSystem, 1)
	r := rows[0]
	if r.Level != "info" || r.Component != "edge" || r.Domain != "app.example.com" || r.Status != 0 ||
		r.Message != "backend injoignable code=502" {
		t.Fatalf("log système stocké = %+v", r)
	}
}

func TestShipEntryFromRowMatchesWhatTheLiveShipperSent(t *testing.T) {
	st, _ := testStore(t)
	al := NewAccessLogger()
	al.SetStore(st)
	al.SetIPProtection(false, true)
	got := make(chan ShipEntry, 1)
	al.SetForwarder(func(batch []ShipEntry) {
		for _, e := range batch {
			select {
			case got <- e:
			default:
			}
		}
	})
	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/missing", nil)
	req.RemoteAddr = "203.0.113.42:5"
	req.Header.Set("User-Agent", "curl/8")
	req.Header.Set("Referer", "https://ref.example/")
	for range 100 { // le lot part à 100 entrées
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	var live ShipEntry
	select {
	case live = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("aucune entrée expédiée en direct")
	}

	st.Flush()
	rows, err := st.ReadAfterRevealed(logstore.KindAccess, 0, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("lecture : %d lignes, %v", len(rows), err)
	}
	replay := ShipEntryFromRow(rows[0], logstore.KindAccess, "edge-1")
	if replay.Seq != rows[0].ID || replay.Seq == 0 || replay.NodeName != "edge-1" {
		t.Fatalf("seq=%d node=%q", replay.Seq, replay.NodeName)
	}
	// Mêmes champs que l'envoi en direct, sauf ce que celui-ci ne porte pas (numéro, nom du nœud).
	live.Seq, live.NodeName, live.Ts, replay.Ts = 0, "", "", ""
	replay.Seq, replay.NodeName = 0, ""
	if live.Message != replay.Message || live.IP != replay.IP || live.RealIP != replay.RealIP || live.Status != replay.Status ||
		live.Domain != replay.Domain || live.Path != replay.Path || live.Level != replay.Level || live.Bytes != replay.Bytes {
		t.Fatalf("rejeu différent de l'envoi en direct :\n live   %+v\n replay %+v", live, replay)
	}
	if replay.RealIP != "203.0.113.42" || replay.IP != "203.0.113.0" || !replay.IPTruncated {
		t.Fatalf("IP du rejeu = %q / %q tronquée=%v", replay.IP, replay.RealIP, replay.IPTruncated)
	}
}

func TestShipEntryFromRowForSystemLines(t *testing.T) {
	r := logstore.Row{ID: 7, Entry: logstore.Entry{Ts: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC), Level: "warn", Component: "edge", Domain: "app.example.com", Message: "backend down"}}
	e := ShipEntryFromRow(r, logstore.KindSystem, "edge-1")
	if e.Message != "backend down" || e.Status != 0 || e.Level != "warn" || e.Seq != 7 || e.Ts != "2026-10-21T10:00:00Z" {
		t.Fatalf("entrée système = %+v", e)
	}
}
