// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeGateway struct {
	mu      sync.Mutex
	posts   []map[string]any
	stops   []map[string]any
	status  int // statut des POST (0 = 204)
	lists   int
	listing []map[string]any
	srv     *httptest.Server
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jeton" {
			http.Error(w, "non autorisé", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			g.posts = append(g.posts, body)
			if g.status != 0 {
				w.WriteHeader(g.status)
				return
			}
		case http.MethodDelete:
			g.stops = append(g.stops, body)
		case http.MethodGet:
			g.lists++
			_ = json.NewEncoder(w).Encode(g.listing)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) counts() (posts, stops int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.posts), len(g.stops)
}

type fakeLister struct {
	mu    sync.Mutex
	insts []Instance
	err   error
}

func (f *fakeLister) List(context.Context) ([]Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Instance(nil), f.insts...), f.err
}

func (f *fakeLister) set(insts []Instance, err error) {
	f.mu.Lock()
	f.insts, f.err = insts, err
	f.mu.Unlock()
}

func web(key, backend string, extra map[string]string) Instance {
	l := map[string]string{"goproxify.enable": "true", "goproxify.host": "app.example.com"}
	for k, v := range extra {
		l[k] = v
	}
	return Instance{Key: key, Name: key, Backend: backend, Labels: l}
}

func newEngine(g *fakeGateway, l Lister) *Engine {
	return New("consul", l, time.Hour, "goproxify.", g.srv.URL, "jeton", "agent-1", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestEngine_PublishesOnlyWhatChanged(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	ctx := context.Background()

	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", map[string]string{"goproxify.tls": "true"}), web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	if p, _ := g.counts(); p != 2 {
		t.Fatalf("première passe : %d envois", p)
	}
	var first map[string]any
	for _, p := range g.posts {
		if be, _ := p["backends"].([]any); len(be) == 1 && be[0] == "http://10.0.0.1:8080" {
			first = p
		}
	}
	if first["host"] != "app.example.com" || first["source"] != "consul" || first["agent_name"] != "agent-1" || first["tls_enabled"] != true {
		t.Fatalf("payload = %v", first)
	}
	if be, _ := first["backends"].([]any); len(be) != 1 || be[0] != "http://10.0.0.1:8080" {
		t.Errorf("backends = %v", first["backends"])
	}
	if g.posts[0]["container_id"] == g.posts[1]["container_id"] {
		t.Error("chaque instance doit avoir son identifiant de conteneur, sans quoi le pool de la passerelle les confond")
	}

	e.cycle(ctx)
	if p, _ := g.counts(); p != 2 {
		t.Errorf("rien n'a changé, %d envois", p)
	}

	l.set([]Instance{web("web-1", "http://10.0.0.9:8080", map[string]string{"goproxify.tls": "true"}), web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	if p, s := g.counts(); p != 3 || s != 0 {
		t.Errorf("une instance a changé d'adresse : %d envois, %d retraits", p, s)
	}

	l.set([]Instance{web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	if p, s := g.counts(); p != 3 || s != 1 {
		t.Errorf("une instance a disparu : %d envois, %d retraits", p, s)
	}
	if g.stops[0]["container_id"] != first["container_id"] || g.stops[0]["action"] != "stop" {
		t.Errorf("retrait = %v", g.stops[0])
	}
}

// Un annuaire qui ne répond pas ne doit rien retirer : la passerelle continue de servir ce qu'elle a (ADR 0006).
func TestEngine_UnreachableDirectoryKeepsRoutes(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	l.set(nil, errors.New("connexion refusée"))
	e.cycle(context.Background())
	if p, s := g.counts(); p != 1 || s != 0 {
		t.Fatalf("%d envois, %d retraits", p, s)
	}
	// Une liste vide obtenue avec succès, elle, retire bien la route.
	l.set(nil, nil)
	e.cycle(context.Background())
	if _, s := g.counts(); s != 1 {
		t.Errorf("retraits = %d", s)
	}
}

func TestEngine_IgnoresInstancesWithoutOptInOrHost(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	noHost := web("a", "http://10.0.0.1:80", nil)
	delete(noHost.Labels, "goproxify.host")
	noEnable := web("b", "http://10.0.0.2:80", nil)
	noEnable.Labels["goproxify.enable"] = "false"
	noBackend := web("c", "", nil)
	l.set([]Instance{noHost, noEnable, noBackend, web("ok", "http://10.0.0.5:80", nil)}, nil)
	e.cycle(context.Background())
	if p, _ := g.counts(); p != 1 {
		t.Fatalf("%d envois (un seul attendu)", p)
	}
}

func TestEngine_ResyncRepublishesEverything(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	e.Resync(context.Background())
	e.cycle(context.Background())
	if p, _ := g.counts(); p != 2 {
		t.Errorf("après Resync : %d envois", p)
	}
	e.cycle(context.Background())
	if p, _ := g.counts(); p != 2 {
		t.Errorf("Resync ne vaut que pour une passe : %d envois", p)
	}
}

func TestEngine_HostChangeLeavesTheOldRoute(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:80", nil)}, nil)
	e.cycle(context.Background())
	l.set([]Instance{web("web-1", "http://10.0.0.1:80", map[string]string{"goproxify.host": "autre.example.com"})}, nil)
	e.cycle(context.Background())
	if p, s := g.counts(); p != 2 || s != 1 {
		t.Fatalf("%d envois, %d retraits", p, s)
	}
}

func TestEngine_GatewayFailuresAreRetriedRefusalsAreNot(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:80", nil)}, nil)

	g.mu.Lock()
	g.status = http.StatusInternalServerError
	g.mu.Unlock()
	e.cycle(context.Background())
	e.cycle(context.Background())
	if p, _ := g.counts(); p != 2 {
		t.Fatalf("une erreur 5xx est rejouée à chaque passe : %d envois", p)
	}

	g.mu.Lock()
	g.status = http.StatusUnprocessableEntity
	g.mu.Unlock()
	e.cycle(context.Background())
	e.cycle(context.Background())
	if p, _ := g.counts(); p != 3 {
		t.Fatalf("un refus définitif n'est pas rejoué tant que rien ne change : %d envois", p)
	}
}

// La passerelle retire un backend d'après les 12 premiers caractères de l'identifiant : deux instances qui ne diffèrent
// qu'à la fin de leur nom ne doivent pas se confondre.
func TestContainerID_FirstTwelveCharsDiffer(t *testing.T) {
	a, b := containerID("consul", "service-a-1@node"), containerID("consul", "service-a-2@node")
	if a[:12] == b[:12] || !strings.HasSuffix(a, "@consul") {
		t.Fatalf("%s %s", a, b)
	}
	if containerID("consul", "x") == containerID("nomad", "x") {
		t.Error("la source entre dans l'identifiant")
	}
}

func TestEngine_SecurityLabelsReachThePayload(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:80", map[string]string{"goproxify.rate_limit": "10/s"})}, nil)
	e.cycle(context.Background())
	if g.posts[0]["rate_limit"] == nil {
		t.Errorf("la limitation de débit demandée en étiquette n'est pas transmise : %v", g.posts[0])
	}
}

func TestPrefixIsNormalised(t *testing.T) {
	g := newFakeGateway(t)
	l := &fakeLister{}
	e := New("nomad", l, time.Hour, "gpx.", g.srv.URL, "jeton", "a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	l.set([]Instance{{Key: "k", Name: "k", Backend: "http://10.0.0.1:80", Labels: map[string]string{"gpx.enable": "true", "gpx.host": "p.example.com"}}}, nil)
	e.cycle(context.Background())
	if len(g.posts) != 1 || g.posts[0]["host"] != "p.example.com" {
		t.Fatalf("posts = %v", g.posts)
	}
}

func TestLabelHelpers(t *testing.T) {
	tags := []string{"web", "goproxify.enable=true", "goproxify.host=a.example.com", "autre.cle=1", "goproxify.tls = true "}
	l := labelsFromTags(tags, "goproxify.")
	if l["goproxify.host"] != "a.example.com" || l["goproxify.tls"] != "true" || len(l) != 3 {
		t.Errorf("labels = %v", l)
	}
	if !hasEnableTag(tags, "goproxify.") || hasEnableTag([]string{"goproxify.enable=false"}, "goproxify.") {
		t.Error("hasEnableTag")
	}
	for name, tc := range map[string]struct {
		labels map[string]string
		addr   string
		port   int
		want   string
	}{
		"défaut":         {nil, "10.0.0.1", 8080, "http://10.0.0.1:8080"},
		"https":          {map[string]string{"goproxify.scheme": "https"}, "10.0.0.1", 8443, "https://10.0.0.1:8443"},
		"schéma inconnu": {map[string]string{"goproxify.scheme": "ftp"}, "10.0.0.1", 80, "http://10.0.0.1:80"},
		"port forcé":     {map[string]string{"goproxify.port": "9000"}, "10.0.0.1", 8080, "http://10.0.0.1:9000"},
		"ipv6":           {nil, "fd00::1", 80, "http://[fd00::1]:80"},
		"sans port":      {nil, "10.0.0.1", 0, ""},
		"sans adresse":   {nil, "", 80, ""},
	} {
		if got := backendURL(tc.labels, "goproxify.", tc.addr, tc.port); got != tc.want {
			t.Errorf("%s : %q, attendu %q", name, got, tc.want)
		}
	}
	if strings.Contains(redactURL("http://u:p@h:1/x?token=secret"), "secret") || strings.Contains(redactURL("http://u:p@h:1/x?token=secret"), "u:p") {
		t.Error("redactURL")
	}
}

func TestEngine_ReconcilesStaleInstancesOnce(t *testing.T) {
	g := newFakeGateway(t)
	stale := containerID("consul", "disparu@n1")
	other := containerID("nomad", "autre@n1")
	g.listing = []map[string]any{{"container_ids": []string{stale, other, "abcdef123456"}}}
	l := &fakeLister{}
	e := newEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:80", nil)}, nil)
	e.cycle(context.Background())
	e.cycle(context.Background())
	if g.lists != 1 {
		t.Errorf("la réconciliation n'a lieu qu'une fois : %d", g.lists)
	}
	if len(g.stops) != 1 || g.stops[0]["container_id"] != stale {
		t.Fatalf("retraits = %v (seule l'instance périmée de cette source doit partir)", g.stops)
	}
}
