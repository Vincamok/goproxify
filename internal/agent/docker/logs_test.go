// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLogDocker rejoue des lignes horodatées comme l'API Docker : seules celles à partir de since sont envoyées,
// puis le flux reste ouvert (follow) jusqu'à l'annulation du contexte. Les lignes ajoutées ensuite sont suivies.
type fakeLogDocker struct {
	mu    sync.Mutex
	lines []fakeLogLine
	since []time.Time // valeur de since reçue à chaque ouverture
}

type fakeLogLine struct {
	t    time.Time
	text string
}

func (d *fakeLogDocker) add(t time.Time, text string) {
	d.mu.Lock()
	d.lines = append(d.lines, fakeLogLine{t, text})
	d.mu.Unlock()
}

func (d *fakeLogDocker) follow(ctx context.Context, path string, fn func([]byte)) error {
	q, _ := url.ParseQuery(path[strings.Index(path, "?")+1:])
	sec, frac, _ := strings.Cut(q.Get("since"), ".")
	s, _ := strconv.ParseInt(sec, 10, 64)
	ns, _ := strconv.ParseInt(frac, 10, 64)
	since := time.Unix(s, ns).UTC()
	d.mu.Lock()
	d.since = append(d.since, since)
	d.mu.Unlock()

	next := 0
	for ctx.Err() == nil {
		d.mu.Lock()
		var batch []fakeLogLine
		for ; next < len(d.lines); next++ {
			if !d.lines[next].t.Before(since) {
				batch = append(batch, d.lines[next])
			}
		}
		d.mu.Unlock()
		for _, l := range batch {
			// 8 octets d'en-tête de trame Docker, puis « horodatage message ».
			fn([]byte("\x01\x00\x00\x00\x00\x00\x00\x00" + l.t.Format(time.RFC3339Nano) + " " + l.text))
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ctx.Err()
}

func (d *fakeLogDocker) sinces() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.since...)
}

// fakeLogGateway reçoit les lots comme /internal/v1/agent/logs : il garde les lignes et peut refuser les envois.
type fakeLogGateway struct {
	mu     sync.Mutex
	got    []string
	reject bool
	posts  int
}

func (g *fakeLogGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.posts++
	if g.reject {
		http.Error(w, "indisponible", http.StatusServiceUnavailable)
		return
	}
	var b logBatch
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range b.Entries {
		g.got = append(g.got, e.Line)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *fakeLogGateway) lines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.got...)
}

func (g *fakeLogGateway) setReject(v bool) {
	g.mu.Lock()
	g.reject = v
	g.mu.Unlock()
}

func newTestForwarder(t *testing.T, d *fakeLogDocker, gwURL, statePath string) *LogForwarder {
	t.Helper()
	f := NewLogForwarder(nil, gwURL, "tok", 100, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.follow = d.follow
	f.flushEvery = 20 * time.Millisecond
	f.retryMin, f.retryMax = 20*time.Millisecond, 50*time.Millisecond
	f.SetStatePath(statePath)
	return f
}

func waitForLog(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func numberedLines(prefix string, from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, fmt.Sprintf("%s-%d", prefix, i))
	}
	return out
}

func TestParseLogLineSeparatesTheDockerTimestamp(t *testing.T) {
	e := parseLogLine([]byte("2026-10-20T11:00:00.123456789Z GET /x 200\r\n"))
	if e.Line != "GET /x 200" || e.T.Format(time.RFC3339Nano) != "2026-10-20T11:00:00.123456789Z" {
		t.Fatalf("ligne = %+v", e)
	}
	// Sans horodatage lisible la ligne reste entière, avec l'heure de lecture.
	raw := parseLogLine([]byte("pas d'horodatage ici"))
	if raw.Line != "pas d'horodatage ici" || time.Since(raw.T) > time.Minute {
		t.Fatalf("ligne sans horodatage = %+v", raw)
	}
}

func TestForwardsLinesWithTheirDockerTimestampAndSavesThePosition(t *testing.T) {
	gw := &fakeLogGateway{}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	d := &fakeLogDocker{}
	state := filepath.Join(t.TempDir(), "cursors.json")
	f := newTestForwarder(t, d, srv.URL, state)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now().UTC()
	f.Watch(ctx, "c1", "web")
	waitForLog(t, "ouverture du flux", func() bool { return len(d.sinces()) > 0 })
	if s := d.sinces()[0]; s.Before(start.Add(-time.Second)) || s.After(time.Now().Add(time.Second)) {
		t.Fatalf("premier suivi depuis %v, attendu maintenant", s)
	}

	last := time.Now().UTC().Add(3 * time.Second)
	d.add(last.Add(-2*time.Second), "un")
	d.add(last.Add(-time.Second), "deux")
	d.add(last, "trois")
	waitForLog(t, "les trois lignes", func() bool { return len(gw.lines()) == 3 })
	if got := strings.Join(gw.lines(), ","); got != "un,deux,trois" {
		t.Fatalf("lignes reçues = %s", got)
	}
	waitForLog(t, "position enregistrée", func() bool {
		c, ok := f.cursor("c1")
		return ok && c.Equal(last.Add(time.Nanosecond))
	})
	// La position survit à un redémarrage de l'Agent.
	g2 := newTestForwarder(t, d, srv.URL, state)
	if c, ok := g2.cursor("c1"); !ok || !c.Equal(last.Add(time.Nanosecond)) {
		t.Fatalf("position relue = %v %v", c, ok)
	}
}

// Une passerelle qui refuse les lots ne fait rien perdre : les lignes sont relues depuis la position et arrivent
// toutes, une fois, dès qu'elle répond.
func TestNothingIsLostWhileTheGatewayIsDown(t *testing.T) {
	gw := &fakeLogGateway{reject: true}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	d := &fakeLogDocker{}
	f := newTestForwarder(t, d, srv.URL, filepath.Join(t.TempDir(), "cursors.json"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Watch(ctx, "c1", "web")
	waitForLog(t, "ouverture du flux", func() bool { return len(d.sinces()) > 0 })
	base := time.Now().UTC().Add(time.Second)
	for i, l := range numberedLines("ligne", 1, 30) {
		d.add(base.Add(time.Duration(i)*time.Millisecond), l)
	}
	waitForLog(t, "plusieurs tentatives refusées", func() bool {
		gw.mu.Lock()
		defer gw.mu.Unlock()
		return gw.posts >= 3
	})
	if n := len(gw.lines()); n != 0 {
		t.Fatalf("%d lignes acquittées alors que la passerelle refuse", n)
	}
	if _, ok := f.cursor("c1"); ok {
		t.Fatal("la position a avancé sans accusé de réception")
	}

	gw.setReject(false)
	want := strings.Join(numberedLines("ligne", 1, 30), ",")
	waitForLog(t, "toutes les lignes après le retour de la passerelle", func() bool { return len(gw.lines()) >= 30 })
	time.Sleep(150 * time.Millisecond) // laisse passer un éventuel doublon
	if got := strings.Join(gw.lines(), ","); got != want {
		t.Fatalf("lignes reçues :\n%s\nattendu :\n%s", got, want)
	}
}

// Après un redémarrage de l'Agent, la lecture reprend à la position enregistrée : ni trou, ni relecture.
func TestResumesFromTheSavedPositionAfterARestart(t *testing.T) {
	gw := &fakeLogGateway{}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	d := &fakeLogDocker{}
	state := filepath.Join(t.TempDir(), "cursors.json")

	ctx1, cancel1 := context.WithCancel(context.Background())
	f1 := newTestForwarder(t, d, srv.URL, state)
	f1.Watch(ctx1, "c1", "web")
	waitForLog(t, "ouverture du flux", func() bool { return len(d.sinces()) > 0 })
	base := time.Now().UTC().Add(time.Second)
	for i, l := range numberedLines("avant", 1, 10) {
		d.add(base.Add(time.Duration(i)*time.Millisecond), l)
	}
	waitForLog(t, "les lignes d'avant l'arrêt", func() bool { return len(gw.lines()) == 10 })
	waitForLog(t, "position enregistrée", func() bool { _, ok := f1.cursor("c1"); return ok })
	cancel1() // l'Agent s'arrête

	// Pendant l'arrêt, le conteneur écrit encore.
	for i, l := range numberedLines("pendant", 1, 15) {
		d.add(base.Add(time.Second+time.Duration(i)*time.Millisecond), l)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	f2 := newTestForwarder(t, d, srv.URL, state)
	f2.Watch(ctx2, "c1", "web")
	waitForLog(t, "les lignes écrites pendant l'arrêt", func() bool { return len(gw.lines()) >= 25 })
	time.Sleep(150 * time.Millisecond)
	want := strings.Join(append(numberedLines("avant", 1, 10), numberedLines("pendant", 1, 15)...), ",")
	if got := strings.Join(gw.lines(), ","); got != want {
		t.Fatalf("lignes reçues :\n%s\nattendu :\n%s", got, want)
	}
}

func TestUnwatchStopsFollowingButKeepsThePosition(t *testing.T) {
	gw := &fakeLogGateway{}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	d := &fakeLogDocker{}
	f := newTestForwarder(t, d, srv.URL, filepath.Join(t.TempDir(), "cursors.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f.Watch(ctx, "c1", "web")
	waitForLog(t, "ouverture du flux", func() bool { return len(d.sinces()) > 0 })
	d.add(time.Now().UTC().Add(time.Second), "une")
	waitForLog(t, "la ligne", func() bool { return len(gw.lines()) == 1 })
	waitForLog(t, "position enregistrée", func() bool { _, ok := f.cursor("c1"); return ok })
	f.Unwatch("c1")
	n := len(d.sinces())
	time.Sleep(200 * time.Millisecond)
	if len(d.sinces()) != n {
		t.Fatal("le flux est rouvert après Unwatch")
	}
	if _, ok := f.cursor("c1"); !ok {
		t.Fatal("la position est perdue après Unwatch")
	}
}
