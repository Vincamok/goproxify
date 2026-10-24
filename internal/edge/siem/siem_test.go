// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func store(t *testing.T) *logstore.Store {
	t.Helper()
	s, err := logstore.Open(logstore.Options{Dir: filepath.Join(t.TempDir(), "logs"),
		Retention: map[logstore.Kind]time.Duration{logstore.KindAccess: 10 * 24 * time.Hour, logstore.KindSystem: 10 * 24 * time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func access(s *logstore.Store, at time.Time, path string, status int, mutate func(*logstore.Entry)) {
	e := logstore.Entry{Ts: at, Level: "info", Component: "edge", Domain: "app.example.com", Method: "GET", Path: path, Status: status,
		IP: "198.51.100.7", Bytes: 10, LatencyMs: 4, RequestID: "req-1"}
	if mutate != nil {
		mutate(&e)
	}
	s.Add(logstore.KindAccess, e)
}

type memState struct {
	mu sync.Mutex
	m  map[string]map[string]int64
}

func (s *memState) Load() (map[string]map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyPositions(s.m), nil
}

func (s *memState) Save(m map[string]map[string]int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = copyPositions(m)
	return nil
}

func copyPositions(in map[string]map[string]int64) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for k, v := range in {
		out[k] = map[string]int64{}
		for kk, vv := range v {
			out[k][kk] = vv
		}
	}
	return out
}

// fakeSender enregistre les lots et peut échouer à la demande.
type fakeSender struct {
	mu       sync.Mutex
	failNext int
	got      []Record
}

func (f *fakeSender) Send(_ context.Context, recs []Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return fmt.Errorf("SIEM injoignable")
	}
	f.got = append(f.got, recs...)
	return nil
}

func (f *fakeSender) Close() {}

func (f *fakeSender) records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.got...)
}

func (f *fakeSender) paths() []string {
	var out []string
	for _, r := range f.records() {
		out = append(out, r.Row.Path)
	}
	return out
}

func wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newManager(s *logstore.Store, st State, f *fakeSender) *Manager {
	return New(Options{Node: "gw-a", Source: s, State: st, NewSender: func(Destination) (Sender, error) { return f, nil },
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		Retention: func(logstore.Kind) time.Duration { return 10 * 24 * time.Hour }})
}

func dest(id string) Destination {
	return Destination{ID: id, Name: "SIEM " + id, Type: TypeHTTP, Address: "http://siem.example/in"}
}

func TestSyslogRecordFollowsRFC5424(t *testing.T) {
	r := Record{Node: "gw a", Kind: "access", Row: logstore.Row{ID: 42, Entry: logstore.Entry{
		Ts: time.Date(2026, 10, 21, 10, 0, 5, 123456000, time.UTC), Level: "warn", Component: "edge", Domain: "app.example.com",
		Method: "GET", Path: `/a"b]c\d`, Status: 403, IP: "203.0.113.9", WAFMatches: []string{"sqli", "xss"}, ThreatSignal: "scan",
		Message: "ligne\navec saut"}}}
	got := string(Syslog(r, 16))
	for _, want := range []string{"<132>1 2026-10-21T10:00:05.123456Z gw_a goproxify - access [gpx@32473 id=\"gw a:access:42\"", `path="/a\"b\]c\\d"`,
		`status="403"`, `ip="203.0.113.9"`, `waf="sqli,xss"`, `threat="scan"`, "] ligne avec saut"} {
		if !strings.Contains(got, want) {
			t.Errorf("le message syslog ne contient pas %q :\n%s", want, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Error("un saut de ligne subsiste dans le message")
	}
	line := string(JSONLine(r))
	var back map[string]any
	if err := json.Unmarshal([]byte(line), &back); err != nil || back["id"] != "gw a:access:42" || back["status"] != 403.0 || back["ip"] != "203.0.113.9" {
		t.Errorf("JSON = %s (%v)", line, err)
	}
	if strings.Contains(line, "\n") {
		t.Error("la ligne JSON contient un saut de ligne")
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{Enabled: true, Destinations: []Destination{dest("a")}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	facility := 30
	bad := map[string]Destination{
		"sans nom":         {ID: "x", Type: TypeHTTP, Address: "http://h/"},
		"type inconnu":     {ID: "x", Name: "n", Type: "kafka", Address: "h:1"},
		"syslog sans port": {ID: "x", Name: "n", Type: TypeSyslog, Address: "siem.example"},
		"http sans schéma": {ID: "x", Name: "n", Type: TypeHTTP, Address: "siem.example/in"},
		"tls sur http":     {ID: "x", Name: "n", Type: TypeHTTP, Address: "http://h/", TLS: true},
		"niveau inconnu":   {ID: "x", Name: "n", Type: TypeHTTP, Address: "http://h/", MinLevel: "verbose"},
		"type de logs":     {ID: "x", Name: "n", Type: TypeHTTP, Address: "http://h/", Kinds: []string{"audit"}},
		"en-tête invalide": {ID: "x", Name: "n", Type: TypeHTTP, Address: "http://h/", Headers: map[string]string{"X\nY": "v"}},
		"facility":         {ID: "x", Name: "n", Type: TypeSyslog, Address: "h:514", Facility: &facility},
	}
	for name, d := range bad {
		if err := (Config{Destinations: []Destination{d}}).Validate(); err == nil {
			t.Errorf("%s : acceptée", name)
		}
	}
	if err := (Config{Destinations: []Destination{dest("a"), dest("a")}}).Validate(); err == nil {
		t.Error("identifiants en double acceptés")
	}
}

func TestExporterStartsFromNowAndDeliversInOrder(t *testing.T) {
	s := store(t)
	now := time.Now()
	access(s, now.Add(-time.Hour), "/avant", 200, nil)
	s.Flush()
	f := &fakeSender{}
	m := newManager(s, &memState{}, f)
	defer m.Close()
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	for i := 1; i <= 5; i++ {
		access(s, now.Add(time.Duration(i)*time.Second), fmt.Sprintf("/p/%d", i), 200, nil)
	}
	s.Flush()
	wait(t, "les 5 lignes", func() bool { return len(f.paths()) == 5 })
	for i, p := range f.paths() {
		if p != fmt.Sprintf("/p/%d", i+1) {
			t.Fatalf("ordre : %v", f.paths())
		}
	}
}

func TestBackfillStartsHoursBack(t *testing.T) {
	s := store(t)
	now := time.Now()
	access(s, now.Add(-5*time.Hour), "/trop-ancien", 200, nil)
	access(s, now.Add(-90*time.Minute), "/a", 200, nil)
	access(s, now.Add(-10*time.Minute), "/b", 200, nil)
	s.Flush()
	f := &fakeSender{}
	m := newManager(s, &memState{}, f)
	defer m.Close()
	d := dest("a")
	d.BackfillHours = 2
	m.Apply(Config{Enabled: true, Destinations: []Destination{d}})
	wait(t, "les deux lignes des deux dernières heures", func() bool { return len(f.paths()) == 2 })
	if p := f.paths(); p[0] != "/a" || p[1] != "/b" {
		t.Fatalf("lignes = %v", p)
	}
}

func TestFiltersKindsLevelsAndSecurity(t *testing.T) {
	s := store(t)
	f := &fakeSender{}
	m := newManager(s, &memState{}, f)
	defer m.Close()
	d := dest("a")
	d.MinLevel, d.SecurityOnly = "warn", true
	m.Apply(Config{Enabled: true, Destinations: []Destination{d}})
	now := time.Now().Add(time.Second)
	access(s, now, "/ordinaire", 200, nil)
	access(s, now, "/waf", 403, func(e *logstore.Entry) { e.WAFMatches = []string{"sqli"}; e.Level = "warn" })
	access(s, now, "/waf-info", 403, func(e *logstore.Entry) { e.WAFMatches = []string{"sqli"} })
	s.Add(logstore.KindSystem, logstore.Entry{Ts: now, Level: "error", Component: "edge", Message: "panne"})
	s.Add(logstore.KindSystem, logstore.Entry{Ts: now, Level: "info", Component: "edge", Message: "bruit"})
	s.Flush()
	wait(t, "les deux lignes retenues", func() bool { return len(f.records()) >= 2 })
	time.Sleep(200 * time.Millisecond)
	got := map[string]bool{}
	for _, r := range f.records() {
		got[r.Kind+":"+r.Row.Path+r.Row.Message] = true
	}
	if len(f.records()) != 2 || !got["access:/waf"] || !got["system:panne"] {
		t.Fatalf("lignes exportées : %v", got)
	}

	f2 := &fakeSender{}
	m2 := newManager(s, &memState{}, f2)
	defer m2.Close()
	d2 := dest("b")
	d2.Kinds = []string{"system"}
	m2.Apply(Config{Enabled: true, Destinations: []Destination{d2}})
	later := time.Now().Add(2 * time.Second)
	s.Add(logstore.KindSystem, logstore.Entry{Ts: later, Level: "info", Component: "edge", Message: "après"})
	access(s, later, "/acces", 200, nil)
	s.Flush()
	wait(t, "le log système", func() bool { return len(f2.records()) >= 1 })
	time.Sleep(200 * time.Millisecond)
	if recs := f2.records(); len(recs) != 1 || recs[0].Kind != "system" {
		t.Fatalf("lignes exportées : %+v", recs)
	}
}

// Un SIEM qui tombe ne fait rien perdre : le lot est renvoyé tel quel, sans trou ni doublon dans ce qui est accepté.
func TestFailedDeliveryIsRetriedWithoutLoss(t *testing.T) {
	s := store(t)
	f := &fakeSender{failNext: 3}
	m := newManager(s, &memState{}, f)
	defer m.Close()
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	now := time.Now().Add(time.Second)
	for i := 1; i <= 4; i++ {
		access(s, now, fmt.Sprintf("/p/%d", i), 200, nil)
	}
	s.Flush()
	wait(t, "les 4 lignes malgré trois échecs", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].Delivered == 4 && st[0].State == "ok"
	})
	if st := m.Status()[0]; st.LagSec != 0 || st.AtRisk {
		t.Fatalf("état : %+v", st)
	}
	ids := map[string]bool{}
	for _, r := range f.records() {
		if ids[r.ID()] {
			t.Errorf("identifiant en double %s", r.ID())
		}
		ids[r.ID()] = true
	}
	if len(ids) != 4 {
		t.Fatalf("lignes livrées : %v", f.paths())
	}
}

func TestPositionsSurviveARestartWithoutReplay(t *testing.T) {
	s := store(t)
	st := &memState{}
	f := &fakeSender{}
	m := newManager(s, st, f)
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	now := time.Now().Add(time.Second)
	for i := 1; i <= 3; i++ {
		access(s, now, fmt.Sprintf("/avant/%d", i), 200, nil)
	}
	s.Flush()
	wait(t, "les 3 premières", func() bool { return len(f.paths()) == 3 })
	m.Close()

	// La passerelle redémarre pendant que le SIEM est coupé : les lignes de la coupure arrivent, pas les anciennes.
	for i := 1; i <= 2; i++ {
		access(s, now, fmt.Sprintf("/pendant/%d", i), 200, nil)
	}
	s.Flush()
	f2 := &fakeSender{}
	m2 := newManager(s, st, f2)
	defer m2.Close()
	m2.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	wait(t, "les lignes de la coupure", func() bool { return len(f2.paths()) >= 2 })
	time.Sleep(100 * time.Millisecond)
	if p := f2.paths(); len(p) != 2 || p[0] != "/pendant/1" || p[1] != "/pendant/2" {
		t.Fatalf("après redémarrage : %v", p)
	}
}

func TestRemovedDestinationLosesItsPositionAndStops(t *testing.T) {
	s := store(t)
	st := &memState{}
	m := newManager(s, st, &fakeSender{})
	defer m.Close()
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a"), dest("b")}})
	if got, _ := st.Load(); len(got) != 2 {
		t.Fatalf("positions : %v", got)
	}
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	if got, _ := st.Load(); len(got) != 1 || got["a"] == nil || len(m.Status()) != 1 {
		t.Fatalf("après retrait : %v, %d destination(s)", got, len(m.Status()))
	}
	m.Apply(Config{Enabled: false, Destinations: []Destination{dest("a")}})
	if got, _ := st.Load(); len(got) != 0 || len(m.Status()) != 0 {
		t.Fatalf("désactivé : %v, %d destination(s)", got, len(m.Status()))
	}
}

// Le retard est l'âge de la plus ancienne ligne non livrée ; au-delà de 80 % de la conservation il est « à risque ».
func TestStatusReportsLagAndRisk(t *testing.T) {
	s := store(t)
	f := &fakeSender{failNext: 1 << 30}
	m := newManager(s, &memState{}, f)
	defer m.Close()
	d := dest("a")
	d.BackfillHours = 24*9 + 1
	d.AlertAfterMinutes = 30
	now := time.Now()
	access(s, now.Add(-9*24*time.Hour), "/vieille", 200, nil)
	access(s, now.Add(-time.Hour), "/recente", 200, nil)
	s.Flush()
	m.Apply(Config{Enabled: true, Destinations: []Destination{d}})
	wait(t, "l'état en échec", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].State == "retrying"
	})
	st := m.Status()[0]
	if st.LagSec < 8*24*3600 || !st.AtRisk || st.AlertAfterMin != 30 || st.LastError == "" || st.Delivered != 0 {
		t.Fatalf("état : %+v", st)
	}
}

// parseFrames lit des messages cadrés par comptage d'octets (RFC 6587).
func parseFrames(r io.Reader, out chan<- string) {
	br := bufio.NewReader(r)
	for {
		n, err := br.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		out <- string(buf)
	}
}

func listen(t *testing.T, cfg *tls.Config) (string, <-chan string) {
	t.Helper()
	var l net.Listener
	var err error
	if cfg != nil {
		l, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		l, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ch := make(chan string, 100)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				parseFrames(c, ch)
			}()
		}
	}()
	return l.Addr().String(), ch
}

func records(n int) []Record {
	var out []Record
	for i := 1; i <= n; i++ {
		out = append(out, Record{Node: "gw-a", Kind: "access", Row: logstore.Row{ID: int64(i), Entry: logstore.Entry{
			Ts: time.Now(), Level: "info", Component: "edge", Method: "GET", Path: fmt.Sprintf("/p/%d", i), Status: 200}}})
	}
	return out
}

func TestSyslogOverTCPUsesOctetCounting(t *testing.T) {
	addr, frames := listen(t, nil)
	sender, err := NewSender(Destination{Type: TypeSyslog, Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := sender.Send(context.Background(), records(3)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		select {
		case m := <-frames:
			if !strings.HasPrefix(m, "<134>1 ") || !strings.Contains(m, fmt.Sprintf("/p/%d", i)) {
				t.Errorf("message %d : %s", i, m)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("message %d non reçu", i)
		}
	}
}

func TestSyslogOverTLSChecksTheCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	addr, frames := listen(t, &tls.Config{Certificates: srv.TLS.Certificates})
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	bad, _ := NewSender(Destination{Type: TypeSyslog, Address: addr, TLS: true})
	if err := bad.Send(context.Background(), records(1)); err == nil {
		t.Error("un certificat inconnu doit être refusé")
	}
	good, err := NewSender(Destination{Type: TypeSyslog, Address: addr, TLS: true, CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	if err := good.Send(context.Background(), records(2)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-frames:
		case <-time.After(5 * time.Second):
			t.Fatal("message non reçu")
		}
	}
	if _, err := NewSender(Destination{Type: TypeSyslog, Address: addr, TLS: true, CAPEM: "pas un certificat"}); err == nil {
		t.Error("une autorité illisible doit être refusée")
	}
}

func TestSyslogReconnectsAfterTheServerDrops(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan string, 10)
	go func() {
		first := true
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if first {
				first = false
				c.Close()
				continue
			}
			go func() { defer c.Close(); parseFrames(c, ch) }()
		}
	}()
	sender, _ := NewSender(Destination{Type: TypeSyslog, Address: l.Addr().String()})
	defer sender.Close()
	delivered := false
	for i := 0; i < 40 && !delivered; i++ {
		if err := sender.Send(context.Background(), records(1)); err == nil {
			select {
			case <-ch:
				delivered = true
			case <-time.After(200 * time.Millisecond):
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !delivered {
		t.Fatal("aucune livraison après la coupure du serveur")
	}
}

func TestHTTPSendsNDJSONWithHeadersAndRetriesOnError(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	fail := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Content-Type") != "application/x-ndjson" {
			http.Error(w, "refusé", http.StatusUnauthorized)
			return
		}
		if fail > 0 {
			fail--
			http.Error(w, "indisponible", http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	sender, _ := NewSender(Destination{Type: TypeHTTP, Address: srv.URL, Headers: map[string]string{"Authorization": "Bearer secret"}})
	defer sender.Close()
	if err := sender.Send(context.Background(), records(3)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("une réponse 503 doit être une erreur : %v", err)
	}
	if err := sender.Send(context.Background(), records(3)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("corps : %v", bodies)
	}
	lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
	if len(lines) != 3 {
		t.Fatalf("lignes : %v", lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["id"] != "gw-a:access:1" {
		t.Errorf("première ligne : %s (%v)", lines[0], err)
	}
}

// Un curseur sauvegardé au-delà de ce que la base a attribué (état restauré sur un disque neuf) ne doit pas faire sauter
// les premières lignes de la nouvelle base.
func TestCursorBeyondTheDatabaseRestartsFromItsBeginning(t *testing.T) {
	s := store(t)
	now := time.Now()
	for i := 1; i <= 4; i++ {
		access(s, now.Add(time.Duration(i)*time.Second), fmt.Sprintf("/neuf/%d", i), 200, nil)
	}
	s.Flush()
	st := &memState{m: map[string]map[string]int64{"a": {"access": 5<<40 | 900, "system": 5<<40 | 900}}}
	f := &fakeSender{}
	m := newManager(s, st, f)
	defer m.Close()
	m.Apply(Config{Enabled: true, Destinations: []Destination{dest("a")}})
	wait(t, "les 4 lignes de la base neuve", func() bool { return len(f.paths()) == 4 })
	if p := f.paths(); p[0] != "/neuf/1" || p[3] != "/neuf/4" {
		t.Fatalf("lignes = %v", p)
	}
	// La position suit désormais la base : une ligne de plus part sans rejeu.
	access(s, now.Add(time.Minute), "/neuf/5", 200, nil)
	s.Flush()
	wait(t, "la ligne suivante", func() bool { return len(f.paths()) == 5 })
}
