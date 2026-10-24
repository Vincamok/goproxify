// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/statepub"
)

type stateGateway struct {
	mu     sync.Mutex
	status int // réponse à l'état complet
	states []map[string]any
	posts  int
	stops  int
	srv    *httptest.Server
}

func newStateGateway(t *testing.T, status int) *stateGateway {
	g := &stateGateway{status: status}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case r.Method == http.MethodPut && r.URL.Path == statepub.Path:
			g.states = append(g.states, body)
			w.WriteHeader(g.status)
			return
		case r.Method == http.MethodPost:
			g.posts++
		case r.Method == http.MethodDelete:
			g.stops++
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *stateGateway) snapshot() (states []map[string]any, posts, stops int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.states...), g.posts, g.stops
}

func stateEngine(g *stateGateway, l Lister) *Engine {
	e := newEngine(&fakeGateway{srv: g.srv}, l)
	e.SetStatePublisher(statepub.New("agent-1", ""))
	return e
}

func routesIn(st map[string]any) int {
	r, _ := st["routes"].([]any)
	return len(r)
}

// L'état complet part quand l'annuaire change, pas à chaque cycle ; aucune instance n'est envoyée seule.
func TestEngineState_SentWhenTheDirectoryChanges(t *testing.T) {
	g := newStateGateway(t, http.StatusOK)
	l := &fakeLister{}
	e := stateEngine(g, l)
	ctx := context.Background()

	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	states, posts, _ := g.snapshot()
	if len(states) != 1 || routesIn(states[0]) != 2 || states[0]["source"] != "consul" || posts != 0 {
		t.Fatalf("un état de 2 instances, aucune route seule : %v, %d envois", states, posts)
	}

	e.cycle(ctx)
	if states, _, _ := g.snapshot(); len(states) != 1 {
		t.Fatalf("rien n'a changé, aucun nouvel envoi : %d", len(states))
	}

	l.set([]Instance{web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	states, _, stops := g.snapshot()
	if len(states) != 2 || routesIn(states[1]) != 1 || stops != 0 {
		t.Fatalf("une instance a disparu : la passerelle la retire d'après l'état, %d états, %d retraits seuls", len(states), stops)
	}
}

func TestEngineState_ResyncSendsAgain(t *testing.T) {
	g := newStateGateway(t, http.StatusOK)
	l := &fakeLister{}
	e := stateEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	e.Resync(context.Background())
	e.cycle(context.Background())
	if states, _, _ := g.snapshot(); len(states) != 2 {
		t.Fatalf("une réannonce renvoie l'état : %d envois", len(states))
	}
}

// Un annuaire qui ne répond pas n'envoie rien : la passerelle garde ses routes.
func TestEngineState_UnreachableDirectorySendsNothing(t *testing.T) {
	g := newStateGateway(t, http.StatusOK)
	l := &fakeLister{}
	e := stateEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	l.set(nil, errors.New("consul injoignable"))
	e.cycle(context.Background())
	if states, _, _ := g.snapshot(); len(states) != 1 {
		t.Fatalf("aucun état vide envoyé sur une erreur de l'annuaire : %d", len(states))
	}
}

// Une passerelle d'avant l'état complet répond 404 : instance par instance, et l'appel n'est pas retenté à chaque cycle.
func TestEngineState_OldGatewayFallsBackToInstances(t *testing.T) {
	g := newStateGateway(t, http.StatusNotFound)
	l := &fakeLister{}
	e := stateEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(context.Background())
	states, posts, _ := g.snapshot()
	if posts != 2 || len(states) != 1 {
		t.Fatalf("repli : %d routes seules, %d tentatives d'état", posts, len(states))
	}
	l.set([]Instance{web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(context.Background())
	states, _, stops := g.snapshot()
	if stops != 1 || len(states) != 1 {
		t.Fatalf("la passerelle ancienne n'est pas sondée à chaque cycle : %d tentatives, %d retraits", len(states), stops)
	}
}

// Un échec de l'envoi ne se double pas de routes seules, et le cycle suivant réessaie.
func TestEngineState_FailureRetriesWithoutFallback(t *testing.T) {
	g := newStateGateway(t, http.StatusInternalServerError)
	l := &fakeLister{}
	e := stateEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	if _, posts, _ := g.snapshot(); posts != 0 {
		t.Fatalf("pas de repli sur un échec : %d", posts)
	}
	g.mu.Lock()
	g.status = http.StatusOK
	g.mu.Unlock()
	e.cycle(context.Background())
	if states, _, _ := g.snapshot(); len(states) != 2 {
		t.Fatalf("le cycle suivant doit réessayer : %d envois", len(states))
	}
}

func inactivesIn(st map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := st["inactive"].([]any)
	for _, v := range list {
		m, _ := v.(map[string]any)
		out = append(out, m)
	}
	return out
}

func unhealthy(key, backend, state string) Instance {
	in := web(key, backend, nil)
	in.Inactive = state
	return in
}

// Une instance que l'annuaire dit inactive (contrôle en échec) n'est pas une route : elle part dans le champ inactive.
func TestEngineState_InactiveInstancesAreNeverRoutes(t *testing.T) {
	g := newStateGateway(t, http.StatusOK)
	l := &fakeLister{}
	e := stateEngine(g, l)
	ctx := context.Background()

	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), unhealthy("web-2", "http://10.0.0.2:8080", "critical")}, nil)
	e.cycle(ctx)
	states, posts, _ := g.snapshot()
	if len(states) != 1 || routesIn(states[0]) != 1 || posts != 0 {
		t.Fatalf("une route (l'instance saine), aucune route seule : %v", states)
	}
	in := inactivesIn(states[0])
	if len(in) != 1 || in[0]["host"] != "app.example.com" || in[0]["state"] != "critical" || in[0]["name"] != "web-2" {
		t.Fatalf("une instance inactive attendue : %v", states[0])
	}

	// Rien n'a changé : aucun nouvel envoi.
	e.cycle(ctx)
	if states, _, _ := g.snapshot(); len(states) != 1 {
		t.Fatalf("aucun nouvel envoi : %d", len(states))
	}

	// L'instance se rétablit : elle devient une route, l'entrée inactive disparaît.
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), web("web-2", "http://10.0.0.2:8080", nil)}, nil)
	e.cycle(ctx)
	states, _, _ = g.snapshot()
	if len(states) != 2 || routesIn(states[1]) != 2 || len(inactivesIn(states[1])) != 0 {
		t.Fatalf("deux routes, plus d'inactif : %v", states)
	}

	// Seul l'état d'une instance inactive change (critical → warning) : c'est un changement.
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), unhealthy("web-2", "http://10.0.0.2:8080", "critical")}, nil)
	e.cycle(ctx)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil), unhealthy("web-2", "http://10.0.0.2:8080", "warning")}, nil)
	e.cycle(ctx)
	states, _, _ = g.snapshot()
	if len(states) != 4 || inactivesIn(states[3])[0]["state"] != "warning" {
		t.Fatalf("le changement d'état de l'inactif est envoyé : %d états", len(states))
	}
}

// Sans instance inactive, l'état n'a pas de champ inactive.
func TestEngineState_NoInactiveFieldWhenAllInstancesServe(t *testing.T) {
	g := newStateGateway(t, http.StatusOK)
	l := &fakeLister{}
	e := stateEngine(g, l)
	l.set([]Instance{web("web-1", "http://10.0.0.1:8080", nil)}, nil)
	e.cycle(context.Background())
	states, _, _ := g.snapshot()
	if _, ok := states[0]["inactive"]; ok {
		t.Fatalf("pas de champ inactive : %v", states[0])
	}
}
