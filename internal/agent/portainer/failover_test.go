// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGateway compte les routes reçues par une passerelle.
type fakeGateway struct {
	srv   *httptest.Server
	mu    sync.Mutex
	posts int
	auth  []string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.Method == http.MethodPost && r.URL.Path == "/internal/v1/agent/containers" {
			g.posts++
			g.auth = append(g.auth, r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.posts
}

// newPortainerAPI sert un endpoint local avec un conteneur portant les labels Goproxify.
func newPortainerAPI(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/endpoints/1/docker/containers/json"):
			io.WriteString(w, `[{"Id":"abcdef0123456789","Names":["/web"],"Image":"nginx","State":"running",
				"Labels":{"goproxify.enable":"true","goproxify.host":"app.example.fr","goproxify.port":"80"},
				"NetworkSettings":{"Networks":{"appnet":{"NetworkID":"n1","IPAddress":"10.0.0.5"}}}}]`)
		case r.URL.Path == "/api/endpoints":
			io.WriteString(w, `[{"Id":1,"Name":"local","URL":"unix:///var/run/docker.sock","Status":1}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestDiscovery(t *testing.T, fixedGateway string, edges map[string]EndpointEdgeInput) *Discovery {
	api := newPortainerAPI(t)
	return NewDiscovery(NewClient(api.URL, "key"), fixedGateway, "agent-token", "goproxify.", "agent-1", 30,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, edges)
}

// Avant correction, Portainer figeait l'adresse de la passerelle à la création : après une bascule
// vers un autre membre du groupe HA, il continuait d'écrire à la passerelle tombée.
func TestPortainer_FollowsTheCurrentGateway(t *testing.T) {
	a, b := newFakeGateway(t), newFakeGateway(t)
	current := a.srv.URL
	d := newTestDiscovery(t, "http://127.0.0.1:1", nil) // adresse fixe volontairement injoignable
	d.SetEndpointFunc(func() string { return current })

	d.Resync(t.Context())
	if a.count() == 0 || b.count() != 0 {
		t.Fatalf("avant la bascule : A=%d B=%d", a.count(), b.count())
	}
	nA := a.count()

	current = b.srv.URL // bascule HA
	d.Resync(t.Context())
	if b.count() == 0 {
		t.Fatalf("après la bascule, la passerelle B n'a rien reçu (A=%d B=%d)", a.count(), b.count())
	}
	if a.count() != nA {
		t.Fatalf("la passerelle A, abandonnée, a encore reçu des routes : %d → %d", nA, a.count())
	}
}

func TestPortainer_FallsBackToTheFixedAddress(t *testing.T) {
	fixed := newFakeGateway(t)
	d := newTestDiscovery(t, fixed.srv.URL, nil)

	d.Resync(t.Context()) // aucune fonction : adresse fixe
	if fixed.count() == 0 {
		t.Fatal("adresse fixe non utilisée sans fonction de passerelle")
	}
	n := fixed.count()
	d.SetEndpointFunc(func() string { return "" }) // la fonction ne connaît rien : repli
	d.Resync(t.Context())
	if fixed.count() <= n {
		t.Fatal("repli sur l'adresse fixe attendu quand la passerelle courante est inconnue")
	}
}

// Une passerelle alternative déclarée pour un endpoint Portainer est un choix de l'opérateur : la
// bascule HA de l'Agent ne la remplace pas.
func TestPortainer_PerEndpointGatewayIsNotOverridden(t *testing.T) {
	explicit, agentGateway := newFakeGateway(t), newFakeGateway(t)
	d := newTestDiscovery(t, "http://127.0.0.1:1", map[string]EndpointEdgeInput{
		"local": {EdgeEndpoint: explicit.srv.URL, AuthToken: "explicit-token"},
	})
	d.SetEndpointFunc(func() string { return agentGateway.srv.URL })

	d.Resync(t.Context())
	if explicit.count() == 0 || agentGateway.count() != 0 {
		t.Fatalf("explicite=%d passerelle de l'Agent=%d", explicit.count(), agentGateway.count())
	}
	if explicit.auth[0] != "Bearer explicit-token" {
		t.Fatalf("jeton = %q", explicit.auth[0])
	}
}

func TestPortainer_TokenFollowsSetToken(t *testing.T) {
	g := newFakeGateway(t)
	d := newTestDiscovery(t, g.srv.URL, nil)
	d.SetToken("paired")
	d.Resync(t.Context())
	if len(g.auth) == 0 || g.auth[0] != "Bearer paired" {
		t.Fatalf("en-têtes = %v", g.auth)
	}
}

// Resync (réannonce) et la boucle périodique ne doivent jamais scanner en même temps.
func TestPortainer_ScansAreSerialized(t *testing.T) {
	g := newFakeGateway(t)
	d := newTestDiscovery(t, g.srv.URL, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.Resync(t.Context()) }()
	}
	wg.Wait()
	if g.count() < 8 {
		t.Fatalf("chaque réannonce doit publier : %d routes pour 8 scans", g.count())
	}
}
