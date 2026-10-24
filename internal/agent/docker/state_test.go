// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/statepub"
)

type stateGateway struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int // réponse à l'état complet
	posts  int
	states []map[string]any
}

func newStateGateway(t *testing.T, stateStatus int) *stateGateway {
	g := &stateGateway{status: stateStatus}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case r.Method == http.MethodPut && r.URL.Path == statepub.Path:
			var st map[string]any
			_ = json.NewDecoder(r.Body).Decode(&st)
			g.states = append(g.states, st)
			w.WriteHeader(g.status)
		case r.Method == http.MethodPost:
			g.posts++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func stateDiscovery(containers *[]map[string]any, gw *stateGateway) *Discovery {
	d := NewDiscovery(fakeDocker(containers), gw.srv.URL, "tok", "goproxify.", "agent-1", nil, quietLogger())
	d.SetStatePublisher(statepub.New("agent-1", ""))
	return d
}

func routesOf(st map[string]any) int {
	r, _ := st["routes"].([]any)
	return len(r)
}

// Une passerelle qui connaît l'état complet reçoit tout ce que Docker publie en un envoi, et aucune route seule.
func TestScanAllSendsTheCompleteState(t *testing.T) {
	gw := newStateGateway(t, http.StatusOK)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr"), webContainer("bbbb2222bbbb2222", "b.example.fr")}
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if len(gw.states) != 1 || routesOf(gw.states[0]) != 2 || gw.states[0]["source"] != "docker" {
		t.Fatalf("un état de 2 routes attendu : %v", gw.states)
	}
	if gw.posts != 0 {
		t.Fatalf("aucune route ne part seule : %d", gw.posts)
	}

	// Plus aucun conteneur Goproxify : l'état vide est envoyé, c'est lui qui fait retirer les routes obsolètes.
	containers = nil
	d.ScanAll(context.Background())
	if len(gw.states) != 2 || routesOf(gw.states[1]) != 0 {
		t.Fatalf("un état vide attendu : %v", gw.states)
	}
}

// Une passerelle d'avant l'état complet répond 404 : l'Agent publie route par route.
func TestScanAllFallsBackToRoutesForAnOldGateway(t *testing.T) {
	gw := newStateGateway(t, http.StatusNotFound)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr"), webContainer("bbbb2222bbbb2222", "b.example.fr")}
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if gw.posts != 2 {
		t.Fatalf("repli : 2 routes attendues, obtenu %d", gw.posts)
	}
}

// Un envoi en échec ne se double pas de routes seules : le drapeau « en retard » relance un scan complet.
func TestScanAllFailedStateMarksDirtyWithoutFallback(t *testing.T) {
	gw := newStateGateway(t, http.StatusInternalServerError)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr")}
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if gw.posts != 0 {
		t.Fatalf("pas de repli sur un échec : %d routes seules", gw.posts)
	}
	if !d.dirty.Load() {
		t.Fatal("l'échec doit marquer l'état comme en retard")
	}
}

// Après un événement, l'Agent renvoie un état complet regroupé : c'est lui qui atteint les autres membres du groupe.
func TestEventSchedulesOneCompleteState(t *testing.T) {
	gw := newStateGateway(t, http.StatusOK)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr")}
	d := stateDiscovery(&containers, gw)
	ctx := context.Background()

	d.scheduleState(ctx) // pas d'état pris par la passerelle : rien n'est programmé
	if d.stateTimer != nil {
		t.Fatal("rien à programmer tant que la passerelle n'a pas pris d'état complet")
	}

	d.ScanAll(ctx)
	if len(gw.states) != 1 {
		t.Fatalf("état initial : %d", len(gw.states))
	}
	// Plusieurs événements rapprochés : un seul état complet.
	for i := 0; i < 5; i++ {
		d.scheduleState(ctx)
	}
	deadline := time.Now().Add(stateAfterEventDelay + 3*time.Second)
	for time.Now().Before(deadline) {
		gw.mu.Lock()
		n := len(gw.states)
		gw.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if len(gw.states) != 2 {
		t.Fatalf("cinq événements rapprochés donnent un seul nouvel état : %d états", len(gw.states))
	}
}

func stoppedContainer(id, host, state string) map[string]any {
	c := webContainer(id, host)
	c["State"] = state
	c["NetworkSettings"] = map[string]any{"Networks": map[string]any{}}
	return c
}

// Un conteneur arrêté, en pause ou qui redémarre part dans le champ inactive de l'état : jamais dans les routes.
func TestScanAllSendsStoppedContainersAsInactive(t *testing.T) {
	gw := newStateGateway(t, http.StatusOK)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr"), stoppedContainer("bbbb2222bbbb2222", "b.example.fr", "exited"), stoppedContainer("cccc3333cccc3333", "c.example.fr", "paused")}
	containers[0]["State"] = "running"
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if len(gw.states) != 1 || routesOf(gw.states[0]) != 1 {
		t.Fatalf("une seule route (celle qui tourne) : %v", gw.states)
	}
	in, _ := gw.states[0]["inactive"].([]any)
	if len(in) != 2 {
		t.Fatalf("deux conteneurs inactifs attendus : %v", gw.states[0])
	}
	states := map[string]string{}
	for _, v := range in {
		m, _ := v.(map[string]any)
		states[m["host"].(string)] = m["state"].(string)
	}
	if states["b.example.fr"] != "exited" || states["c.example.fr"] != "paused" {
		t.Fatalf("états inactifs : %v", states)
	}
}

// Sans conteneur arrêté, l'état n'a pas de champ inactive : une passerelle ancienne reçoit exactement ce qu'elle connaît.
func TestScanAllOmitsInactiveWhenEveryContainerRuns(t *testing.T) {
	gw := newStateGateway(t, http.StatusOK)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr")}
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if _, ok := gw.states[0]["inactive"]; ok {
		t.Fatalf("pas de champ inactive : %v", gw.states[0])
	}
}

// Une passerelle ancienne ne reçoit que des routes seules : un conteneur arrêté n'y devient jamais une route.
func TestScanAllOldGatewayNeverGetsAStoppedContainerAsARoute(t *testing.T) {
	gw := newStateGateway(t, http.StatusNotFound)
	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr"), stoppedContainer("bbbb2222bbbb2222", "b.example.fr", "exited")}
	d := stateDiscovery(&containers, gw)

	d.ScanAll(context.Background())
	if gw.posts != 1 {
		t.Fatalf("seule la route du conteneur qui tourne part : %d", gw.posts)
	}
}

// Docker ne liste les conteneurs arrêtés que si la liste le demande (all=true) : sans ce paramètre, un conteneur arrêté
// disparaît comme s'il était supprimé. Le faux Docker ci-dessous se comporte comme le vrai.
func TestScanAllAsksForStoppedContainers(t *testing.T) {
	gw := newStateGateway(t, http.StatusOK)
	running := webContainer("aaaa1111aaaa1111", "a.example.fr")
	running["State"] = "running"
	stopped := stoppedContainer("bbbb2222bbbb2222", "b.example.fr", "exited")
	var queries []string
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		queries = append(queries, r.URL.RawQuery)
		list := []map[string]any{running}
		if r.URL.Query().Get("all") == "true" {
			list = append(list, stopped)
		}
		body, _ := json.Marshal(list)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}}
	d := NewDiscovery(client, gw.srv.URL, "tok", "goproxify.", "agent-1", nil, quietLogger())
	d.SetStatePublisher(statepub.New("agent-1", ""))

	d.ScanAll(context.Background())
	if len(queries) == 0 || queries[0] != "all=true" {
		t.Fatalf("la liste doit demander les conteneurs arrêtés : %v", queries)
	}
	in, _ := gw.states[0]["inactive"].([]any)
	if len(gw.states) != 1 || len(in) != 1 {
		t.Fatalf("le conteneur arrêté doit être envoyé comme inactif : %v", gw.states)
	}
}
