// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/statepub"
)

// recordingGateway note ce que reçoit une passerelle. supportsState : répond 200 à l'état complet ; sinon 404, comme
// une passerelle d'avant cet appel.
type recordingGateway struct {
	srv           *httptest.Server
	supportsState bool

	mu     sync.Mutex
	posts  []string
	dels   []string
	states []map[string]any
}

func newRecordingGateway(t *testing.T, supportsState bool) *recordingGateway {
	g := &recordingGateway{supportsState: supportsState}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPut && r.URL.Path == statepub.Path:
			if !g.supportsState {
				http.NotFound(w, r)
				return
			}
			var st map[string]any
			_ = json.Unmarshal(body, &st)
			g.states = append(g.states, st)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost:
			var p map[string]any
			_ = json.Unmarshal(body, &p)
			g.posts = append(g.posts, fmt.Sprint(p["id"]))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			var p map[string]any
			_ = json.Unmarshal(body, &p)
			g.dels = append(g.dels, fmt.Sprint(p["name"]))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *recordingGateway) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.posts, g.dels, g.states = nil, nil, nil
}

// scopes rend l'endpoint de chaque état complet reçu, et le nombre de routes qu'il portait.
func (g *recordingGateway) scopes() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]int{}
	for _, st := range g.states {
		routes, _ := st["routes"].([]any)
		out[fmt.Sprint(st["scope"])] = len(routes)
	}
	return out
}

// twoEndpointsPortainer sert deux endpoints TCP distants (1 « alpha », 2 « beta ») ; beta peut tomber ou se vider.
type twoEndpointsPortainer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	betaDown bool
	betaNone bool
	// alphaStopped : alpha liste en plus un conteneur à l'état donné (« exited », « paused »…).
	alphaStopped string
}

func newTwoEndpointsPortainer(t *testing.T) *twoEndpointsPortainer {
	p := &twoEndpointsPortainer{}
	containerIn := func(id, host, state string) string {
		return fmt.Sprintf(`{"Id":%q,"Names":["/%s"],"Image":"nginx","State":%q,
			"Labels":{"goproxify.enable":"true","goproxify.host":%q,"goproxify.port":"80"},
			"Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],
			"NetworkSettings":{"Networks":{}}}`, id, host, state, host)
	}
	container := func(id, host string) string { return containerIn(id, host, "running") }
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		switch {
		case r.URL.Path == "/api/endpoints":
			io.WriteString(w, `[{"Id":1,"Name":"alpha","URL":"tcp://10.1.1.1:2375","Status":1},{"Id":2,"Name":"beta","URL":"tcp://10.2.2.2:2375","Status":1}]`)
		case strings.HasPrefix(r.URL.Path, "/api/endpoints/1/docker/containers/json"):
			list := container("aaaaaaaaaaaa1111", "a.example.fr")
			// Comme Docker : sans all=true, seuls les conteneurs qui tournent sont listés.
			if p.alphaStopped != "" && r.URL.Query().Get("all") == "true" {
				list += "," + containerIn("cccccccccccc3333", "c.example.fr", p.alphaStopped)
			}
			io.WriteString(w, "["+list+"]")
		case strings.HasPrefix(r.URL.Path, "/api/endpoints/2/docker/containers/json"):
			switch {
			case p.betaDown:
				http.Error(w, "délai dépassé", http.StatusGatewayTimeout)
			case p.betaNone:
				io.WriteString(w, "[]")
			default:
				io.WriteString(w, "["+container("bbbbbbbbbbbb2222", "b.example.fr")+"]")
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *twoEndpointsPortainer) set(down, none bool) {
	p.mu.Lock()
	p.betaDown, p.betaNone = down, none
	p.mu.Unlock()
}

func newStateDiscovery(t *testing.T, api *twoEndpointsPortainer, gw *recordingGateway) *Discovery {
	d := NewDiscovery(NewClient(api.srv.URL, "key"), gw.srv.URL, "agent-token", "goproxify.", "ag", 30,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil)
	d.SetStatePublisher(statepub.New("ag", ""))
	return d
}

// Avec une passerelle qui connaît l'état complet : un envoi par endpoint, plus aucune route envoyée seule, et un
// endpoint dont la liste échoue n'envoie rien.
func TestPortainerState_OneStatePerEndpointAndNothingForAFailedOne(t *testing.T) {
	api := newTwoEndpointsPortainer(t)
	gw := newRecordingGateway(t, true)
	d := newStateDiscovery(t, api, gw)

	d.Resync(t.Context())
	if got := gw.scopes(); got["1"] != 1 || got["2"] != 1 || len(got) != 2 {
		t.Fatalf("un état complet par endpoint attendu, obtenu %v", got)
	}
	if len(gw.posts) != 0 {
		t.Fatalf("aucune route ne part seule quand l'état complet est accepté : %v", gw.posts)
	}

	gw.reset()
	api.set(true, false) // beta ne répond plus
	d.Resync(t.Context())
	if got := gw.scopes(); got["1"] != 1 || len(got) != 1 {
		t.Fatalf("beta en échec n'envoie rien, obtenu %v", got)
	}
	if len(gw.dels) != 0 {
		t.Fatalf("aucun retrait pour un endpoint injoignable : %v", gw.dels)
	}

	gw.reset()
	api.set(false, true) // beta répond, sans aucun conteneur
	d.Resync(t.Context())
	if got := gw.scopes(); got["2"] != 0 || len(got) != 2 {
		t.Fatalf("un endpoint vide envoie un état vide (la passerelle retire ses routes), obtenu %v", got)
	}
	if _, ok := gw.scopes()["2"]; !ok {
		t.Fatal("l'état vide de beta doit être envoyé")
	}
}

// Avec une passerelle ancienne (état complet inconnu) : l'Agent publie route par route, et l'endpoint injoignable ne
// fait plus retirer ses routes (il les retirait avant, d'où des domaines qui répondaient mal le temps d'un délai).
func TestPortainerState_OldGatewayKeepsRoutesOfAFailedEndpoint(t *testing.T) {
	api := newTwoEndpointsPortainer(t)
	gw := newRecordingGateway(t, false)
	d := newStateDiscovery(t, api, gw)

	d.Resync(t.Context())
	if len(gw.posts) != 2 {
		t.Fatalf("repli route par route : 2 routes attendues, obtenu %v", gw.posts)
	}

	gw.reset()
	api.set(true, false)
	d.Resync(t.Context())
	if len(gw.dels) != 0 {
		t.Fatalf("un endpoint qui ne répond pas ne doit pas faire retirer ses routes : %v", gw.dels)
	}

	gw.reset()
	api.set(false, true) // beta répond vraiment sans conteneur : retrait
	d.Resync(t.Context())
	if len(gw.dels) != 1 || !strings.Contains(gw.dels[0], "2:beta:bbbbbbbbbbbb2222") {
		t.Fatalf("la route de beta doit être retirée, obtenu %v", gw.dels)
	}
}

// inactives rend les conteneurs inactifs du dernier état reçu pour un endpoint.
func (g *recordingGateway) inactives(scope string) []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []map[string]any
	for _, st := range g.states {
		if fmt.Sprint(st["scope"]) != scope {
			continue
		}
		out = nil
		list, _ := st["inactive"].([]any)
		for _, v := range list {
			m, _ := v.(map[string]any)
			out = append(out, m)
		}
	}
	return out
}

// Un conteneur arrêté, en pause ou qui redémarre part dans le champ inactive de l'état : jamais dans les routes.
func TestPortainerState_StoppedContainersAreInactiveNotRoutes(t *testing.T) {
	for _, state := range []string{"exited", "paused", "restarting", "created"} {
		api := newTwoEndpointsPortainer(t)
		api.alphaStopped = state
		gw := newRecordingGateway(t, true)
		d := newStateDiscovery(t, api, gw)

		d.Resync(t.Context())
		if got := gw.scopes(); got["1"] != 1 {
			t.Fatalf("%s : seul le conteneur qui tourne est une route : %v", state, got)
		}
		in := gw.inactives("1")
		if len(in) != 1 || in[0]["host"] != "c.example.fr" || in[0]["state"] != state || in[0]["container_id"] != "cccccccccccc3333" {
			t.Fatalf("%s : un conteneur inactif attendu : %v", state, in)
		}
		if got := gw.inactives("2"); len(got) != 0 {
			t.Fatalf("beta n'a aucun conteneur arrêté : %v", got)
		}
	}
}

// Une passerelle ancienne ne reçoit que des routes seules : un conteneur arrêté n'y devient jamais une route.
func TestPortainerState_OldGatewayNeverGetsAStoppedContainerAsARoute(t *testing.T) {
	api := newTwoEndpointsPortainer(t)
	api.alphaStopped = "exited"
	gw := newRecordingGateway(t, false)
	d := newStateDiscovery(t, api, gw)

	d.Resync(t.Context())
	for _, id := range gw.posts {
		if strings.Contains(id, "cccccccccccc") {
			t.Fatalf("le conteneur arrêté ne doit pas être publié comme route : %v", gw.posts)
		}
	}
	if len(gw.posts) != 2 {
		t.Fatalf("2 routes attendues : %v", gw.posts)
	}
}
