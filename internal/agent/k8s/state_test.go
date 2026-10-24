// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/statepub"
)

type fakeAPI struct {
	srv         *httptest.Server
	mu          sync.Mutex
	failIngress bool
	endpoints   string   // réponse de la liste des Endpoints ; vide : l'API ne les sert pas (404, droit absent)
	watches     []string // requêtes de watch reçues
}

func newFakeAPI(t *testing.T) *fakeAPI {
	a := &fakeAPI{}
	svc := `{"metadata":{"resourceVersion":"100"},"items":[
		{"metadata":{"name":"web-a","namespace":"default","annotations":{"goproxify.host":"a.example.fr","goproxify.backend":"http://a:80"}}},
		{"metadata":{"name":"web-b","namespace":"default","annotations":{"goproxify.host":"b.example.fr","goproxify.backend":"http://b:80"}}}]}`
	ing := `{"metadata":{"resourceVersion":"200"},"items":[
		{"metadata":{"name":"site","namespace":"prod","annotations":{"goproxify.backend":"http://site:80"}},
		 "spec":{"rules":[{"host":"site.example.fr"}]}}]}`
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "1" {
			a.mu.Lock()
			a.watches = append(a.watches, r.URL.Path+"?"+r.URL.RawQuery)
			a.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		switch r.URL.Path {
		case "/api/v1/services":
			w.Write([]byte(svc))
		case "/api/v1/endpoints":
			a.mu.Lock()
			eps := a.endpoints
			a.mu.Unlock()
			if eps == "" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Write([]byte(eps))
		case "/apis/networking.k8s.io/v1/ingresses":
			a.mu.Lock()
			fail := a.failIngress
			a.mu.Unlock()
			if fail {
				http.Error(w, "indisponible", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(ing))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) watchRequests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.watches...)
}

type stateGateway struct {
	srv     *httptest.Server
	mu      sync.Mutex
	status  int
	states  []map[string]any
	posts   int
	deleted []string
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
		case r.Method == http.MethodDelete:
			g.deleted = append(g.deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *stateGateway) snapshot() (states []map[string]any, posts int, deleted []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.states...), g.posts, append([]string(nil), g.deleted...)
}

// startWithState lance la découverte et attend l'ouverture des deux watches.
func startWithState(t *testing.T, api *fakeAPI, gw *stateGateway) (*Discovery, context.CancelFunc) {
	t.Helper()
	d := testDiscovery(t, gw.srv.URL)
	d.apiServer = api.srv.URL
	d.resync = make(chan struct{}, 1)
	d.SetStatePublisher(statepub.New("agent-k8s", ""))
	ctx, cancel := context.WithCancel(context.Background())
	go d.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(api.watchRequests()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(api.watchRequests()) < 2 {
		cancel()
		t.Fatalf("watches ouverts : %v", api.watchRequests())
	}
	return d, cancel
}

// L'état complet part avant les watches, qui reprennent à la version des listes : plus de rejeu des routes une à une.
func TestK8sState_SentBeforeWatchesWhichResumeFromTheListVersion(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	d, cancel := startWithState(t, api, gw)
	defer cancel()

	states, posts, _ := gw.snapshot()
	if len(states) != 1 || states[0]["source"] != "k8s" {
		t.Fatalf("un état complet attendu : %v", states)
	}
	if routes, _ := states[0]["routes"].([]any); len(routes) != 3 {
		t.Fatalf("2 Services et 1 Ingress, soit 3 routes : %v", states[0]["routes"])
	}
	if posts != 0 {
		t.Fatalf("aucune route ne part seule : %d", posts)
	}
	var svcWatch, ingWatch string
	for _, w := range api.watchRequests() {
		if strings.HasPrefix(w, "/api/v1/services") {
			svcWatch = w
		} else {
			ingWatch = w
		}
	}
	if !strings.Contains(svcWatch, "resourceVersion=100") || !strings.Contains(ingWatch, "resourceVersion=200") {
		t.Fatalf("les watches reprennent à la version de leur liste : %q %q", svcWatch, ingWatch)
	}

	// Les suppressions suivantes retrouvent l'hôte de la route : l'état complet a rempli la table des hôtes.
	d.deleteByKey(context.Background(), "default/web-a")
	if _, _, del := gw.snapshot(); len(del) != 1 || !strings.Contains(del[0], "a.example.fr") {
		t.Fatalf("suppression après l'état complet : %v", del)
	}
}

// Il faut les deux listes : un état sans les Ingress retirerait leurs routes.
func TestK8sState_NothingSentWhenOneListFails(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	api.mu.Lock()
	api.failIngress = true
	api.mu.Unlock()
	_, cancel := startWithState(t, api, gw)
	defer cancel()

	if states, _, _ := gw.snapshot(); len(states) != 0 {
		t.Fatalf("aucun état partiel : %v", states)
	}
	for _, w := range api.watchRequests() {
		if strings.Contains(w, "resourceVersion") {
			t.Fatalf("sans état envoyé les watches rejouent l'existant : %q", w)
		}
	}
}

// Une passerelle d'avant l'état complet : les watches rejouent l'existant, route par route, comme avant.
func TestK8sState_OldGatewayKeepsTheReplay(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusNotFound)
	_, cancel := startWithState(t, api, gw)
	defer cancel()

	for _, w := range api.watchRequests() {
		if strings.Contains(w, "resourceVersion") {
			t.Fatalf("passerelle ancienne : pas de reprise à une version : %q", w)
		}
	}
}

// Un état en échec marque l'agent « en retard » : la boucle de reprise le renverra.
func TestK8sState_FailedSendMarksDirty(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusInternalServerError)
	d, cancel := startWithState(t, api, gw)
	defer cancel()
	if !d.dirty.Load() {
		t.Fatal("un état en échec doit marquer l'Agent comme en retard")
	}
}

// Un changement renvoie un seul état complet regroupé, sans relancer les watches : il atteint les autres membres du groupe.
func TestK8sState_EventsScheduleOneCompleteState(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	d, cancel := startWithState(t, api, gw)
	defer cancel()
	ctx := context.Background()
	opens := len(api.watchRequests())

	for i := 0; i < 5; i++ {
		d.scheduleState(ctx)
	}
	deadline := time.Now().Add(stateAfterEventDelay + 4*time.Second)
	for time.Now().Before(deadline) {
		if states, _, _ := gw.snapshot(); len(states) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if states, _, _ := gw.snapshot(); len(states) != 2 {
		t.Fatalf("cinq événements rapprochés donnent un seul nouvel état : %d états", len(states))
	}
	if got := len(api.watchRequests()); got != opens {
		t.Fatalf("les watches ne sont pas relancés : %d ouvertures, %d avant", got, opens)
	}
}

func TestK8sState_NoStateScheduledForAnOldGateway(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusNotFound)
	d, cancel := startWithState(t, api, gw)
	defer cancel()
	d.scheduleState(context.Background())
	d.mu.Lock()
	timer := d.stateTimer
	d.mu.Unlock()
	if timer != nil {
		t.Fatal("rien à programmer tant que la passerelle n'a pas pris d'état complet")
	}
}

func inactiveOf(st map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := st["inactive"].([]any)
	for _, v := range list {
		m, _ := v.(map[string]any)
		out = append(out, m)
	}
	return out
}

const endpointsWebAReady = `{"items":[
	{"metadata":{"name":"web-a","namespace":"default"},"subsets":[{"addresses":[{"ip":"10.0.0.1"}]}]},
	{"metadata":{"name":"web-b","namespace":"default"}}]}`

// Un Service dont l'objet Endpoints n'a aucune adresse prête (zéro réplique, pods pas prêts) n'est pas une route : il part
// dans le champ inactive. Les autres Services et les Ingress restent des routes.
func TestK8sState_ServiceWithoutReadyEndpointsIsInactive(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	api.endpoints = endpointsWebAReady
	_, cancel := startWithState(t, api, gw)
	defer cancel()

	states, posts, _ := gw.snapshot()
	if len(states) != 1 {
		t.Fatalf("un état complet attendu : %v", states)
	}
	if routes, _ := states[0]["routes"].([]any); len(routes) != 2 {
		t.Fatalf("web-a et l'Ingress restent des routes : %v", states[0]["routes"])
	}
	in := inactiveOf(states[0])
	if len(in) != 1 || in[0]["host"] != "b.example.fr" || in[0]["state"] != "no-endpoints" || in[0]["container_id"] != "k8s:default/web-b" {
		t.Fatalf("web-b est inactif : %v", in)
	}
	if posts != 0 {
		t.Fatalf("aucune route seule : %d", posts)
	}
}

// Sans le droit de lire les Endpoints, ou si la liste échoue, aucun Service n'est donné inactif : ne pas savoir n'est pas
// être arrêté.
func TestK8sState_UnreadableEndpointsMakeNothingInactive(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	_, cancel := startWithState(t, api, gw)
	defer cancel()

	states, _, _ := gw.snapshot()
	if routes, _ := states[0]["routes"].([]any); len(routes) != 3 {
		t.Fatalf("les trois routes restent : %v", states[0]["routes"])
	}
	if _, ok := states[0]["inactive"]; ok {
		t.Fatalf("pas de champ inactive : %v", states[0])
	}
}

// Un Service sans objet Endpoints (ExternalName) reste une route.
func TestK8sState_ServiceWithoutEndpointsObjectStaysARoute(t *testing.T) {
	api, gw := newFakeAPI(t), newStateGateway(t, http.StatusOK)
	api.endpoints = `{"items":[{"metadata":{"name":"web-a","namespace":"default"},"subsets":[{"addresses":[{"ip":"10.0.0.1"}]}]}]}`
	_, cancel := startWithState(t, api, gw)
	defer cancel()

	states, _, _ := gw.snapshot()
	if routes, _ := states[0]["routes"].([]any); len(routes) != 3 {
		t.Fatalf("trois routes : %v", states[0]["routes"])
	}
	if len(inactiveOf(states[0])) != 0 {
		t.Fatalf("aucun inactif : %v", states[0])
	}
}
