// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
)

func testDiscovery(t *testing.T, adminURL string) *Discovery {
	t.Helper()
	cfg := &config.AgentConfig{}
	cfg.Identity.NodeName = "agent-k8s"
	return &Discovery{
		cfg:         cfg,
		adminURL:    adminURL,
		authToken:   "tok",
		labelPrefix: "goproxify.",
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		client:      http.DefaultClient,
		hostByKey:   map[string]string{},
	}
}

// Les annotations d'un Ingress suivent la sémantique des labels Docker : elles atteignent le payload.
func TestUpsertIngressAnnotationsReachPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := testDiscovery(t, srv.URL)

	var ing k8sIngress
	ing.Metadata = k8sMeta{Name: "web", Namespace: "prod", Annotations: map[string]string{
		"goproxify.waf":            "block",
		"goproxify.rate_limit":     "100/s:50",
		"goproxify.limit_conn":     "25",
		"goproxify.backpressure":   "200:100:2s",
		"goproxify.slow_start":     "30s",
		"goproxify.jwt":            "https://idp.example.com/jwks.json",
		"goproxify.headers.remove": "X-Powered-By",
		"other.io/ignored":         "x",
	}}
	ing.Spec.Rules = []ingressRule{{Host: "app.example.fr"}}
	ing.Spec.TLS = []ingressTLS{{Hosts: []string{"app.example.fr"}}}
	ing.Metadata.Annotations["goproxify.backend"] = "http://web.prod.svc.cluster.local:8080"
	d.upsertIngress(context.Background(), ing)

	if got == nil {
		t.Fatal("aucune route poussée")
	}
	if got["host"] != "app.example.fr" || got["tls_enabled"] != true || got["source"] != "k8s" {
		t.Fatalf("base: %v", got)
	}
	for _, key := range []string{"waf", "rate_limit", "limit_conn", "backpressure", "slow_start_sec", "jwt", "headers_remove"} {
		if got[key] == nil {
			t.Errorf("annotation non transmise au payload : %s", key)
		}
	}
	if lc, _ := got["limit_conn"].(map[string]any); lc["max_per_ip"] != float64(25) {
		t.Errorf("limit_conn = %v", got["limit_conn"])
	}
	if d.hostByKey["ing:prod/web:app.example.fr"] != "app.example.fr" {
		t.Errorf("hostByKey = %v", d.hostByKey)
	}
}

// Une annotation host en CSV (Service) donne un host principal et des alias, comme les labels Docker.
func TestUpsertServiceHostCSVAndPrefix(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := testDiscovery(t, srv.URL)
	d.labelPrefix = "gpx.example.io/"

	var svc k8sService
	svc.Metadata = k8sMeta{Name: "api", Namespace: "prod", Annotations: map[string]string{
		"gpx.example.io/host":  "api.example.fr, api2.example.fr",
		"gpx.example.io/port":  "9000",
		"gpx.example.io/cache": "60s",
	}}
	svc.Spec.ClusterIP = "10.1.2.3"
	d.upsertService(context.Background(), svc)

	if got["host"] != "api.example.fr" {
		t.Fatalf("host = %v", got["host"])
	}
	if a, _ := got["aliases"].([]any); len(a) != 1 || a[0] != "api2.example.fr" {
		t.Fatalf("aliases = %v", got["aliases"])
	}
	if b, _ := got["backends"].([]any); len(b) != 1 || b[0] != "http://10.1.2.3:9000" {
		t.Fatalf("backends = %v", got["backends"])
	}
	if got["cache"] == nil {
		t.Fatal("annotation cache (préfixe personnalisé) non transmise")
	}
}

// Une annotation ne peut pas détourner le backend ni l hôte déduits de la ressource K8s.
func TestAnnotationsCannotOverrideResourceHost(t *testing.T) {
	d := testDiscovery(t, "http://unused")
	payload, _ := d.routePayload("k", map[string]string{"goproxify.host": "evil.example.fr", "goproxify.enable": "false"},
		"real.example.fr", "http://svc:80", false)
	if payload == nil || payload["host"] != "real.example.fr" {
		t.Fatalf("payload = %v", payload)
	}
}

// Un agent appairé après la construction de la découverte lui transmet son jeton : les routes
// poussées ensuite sont authentifiées avec le nouveau jeton, pas avec celui d'origine (vide si
// l'appairage se fait à l'exécution).
func TestSetTokenIsUsedForRouteRequests(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := testDiscovery(t, srv.URL)
	d.authToken = ""

	push := func() {
		d.pushRoute(context.Background(), "prod/web", map[string]string{"goproxify.backend": "http://web:80"}, "app.example.fr", "http://web:80", false)
	}
	push()
	d.SetToken("paired-token")
	push()
	d.deleteByKey(context.Background(), "prod/web")

	if len(auth) < 2 || auth[0] != "Bearer" || auth[1] != "Bearer paired-token" {
		t.Fatalf("en-têtes Authorization = %v", auth)
	}
}

// Avant correction, la découverte Kubernetes figeait l'adresse de la passerelle à la création : après
// une bascule vers un autre membre du groupe HA, ses routes partaient vers la passerelle tombée.
func TestEndpointFollowsTheCurrentGateway(t *testing.T) {
	var hitsA, hitsB int
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsA++; w.WriteHeader(http.StatusNoContent) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB++; w.WriteHeader(http.StatusNoContent) }))
	defer b.Close()

	d := testDiscovery(t, "http://127.0.0.1:1") // adresse fixe volontairement injoignable
	current := a.URL
	d.SetEndpointFunc(func() string { return current })
	push := func() {
		d.pushRoute(context.Background(), "prod/web", map[string]string{"goproxify.backend": "http://web:80"}, "app.example.fr", "http://web:80", false)
	}

	push()
	d.deleteByKey(context.Background(), "prod/web")
	if hitsA == 0 || hitsB != 0 {
		t.Fatalf("avant la bascule : A=%d B=%d", hitsA, hitsB)
	}
	nA := hitsA

	current = b.URL // bascule HA
	push()
	if hitsB == 0 || hitsA != nA {
		t.Fatalf("après la bascule : A=%d (était %d) B=%d", hitsA, nA, hitsB)
	}

	d.SetEndpointFunc(func() string { return "" }) // passerelle courante inconnue : adresse fixe
	if got := d.endpoint(); got != "http://127.0.0.1:1" {
		t.Fatalf("repli = %q", got)
	}
}

// Un Service ou un Ingress inchangé ne génère aucun événement : après une bascule, seule une relance
// des watches (qui renvoient l'état courant) republie les routes vers la nouvelle passerelle.
func TestResyncRestartsTheWatches(t *testing.T) {
	var mu sync.Mutex
	opens := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		opens++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // le watch reste ouvert jusqu'à ce que le client le coupe
	}))
	defer api.Close()

	d := testDiscovery(t, "http://127.0.0.1:1")
	d.apiServer = api.URL
	d.resync = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Start(ctx); close(done) }()

	waitOpens := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := opens
			mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("watches ouverts = %d, attendu au moins %d", opens, want)
	}

	waitOpens(2) // Services + Ingress
	d.Resync(ctx)
	waitOpens(4) // relancés
	d.Resync(ctx)
	d.Resync(ctx) // les demandes en double ne s'empilent pas
	waitOpens(6)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start ne s'arrête pas à l'annulation du contexte")
	}
}

// Un envoi qui échoue (passerelle injoignable un instant) ne doit pas laisser l'état publié en retard
// jusqu'à la prochaine bascule : la boucle de reprise réannonce tout au prochain passage.
func TestFailedPushTriggersAResync(t *testing.T) {
	up := false
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gw.Close()
	d := testDiscovery(t, gw.URL)
	d.resync = make(chan struct{}, 1)
	push := func() {
		d.pushRoute(context.Background(), "prod/web", map[string]string{"goproxify.backend": "http://web:80"}, "app.example.fr", "http://web:80", false)
	}

	push() // 503
	if !d.dirty.Load() {
		t.Fatal("un 503 doit marquer l'état comme en retard")
	}
	d.retryOnce(context.Background())
	select {
	case <-d.resync:
	default:
		t.Fatal("la reprise doit demander une réannonce")
	}
	if d.dirty.Load() {
		t.Fatal("le drapeau doit être consommé par la réannonce")
	}

	up = true
	push()
	d.retryOnce(context.Background())
	select {
	case <-d.resync:
		t.Fatal("aucune réannonce attendue quand tout est parti")
	default:
	}

	// Injoignable (erreur réseau) : même effet.
	gw.Close()
	push()
	if !d.dirty.Load() {
		t.Fatal("une erreur réseau doit marquer l'état comme en retard")
	}
}

// Une suppression perdue laissait la route sur la passerelle : elle est mémorisée et rejouée, sauf si
// la ressource réapparaît entre-temps.
func TestFailedDeleteIsRetried(t *testing.T) {
	up := false
	var deleted []string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if !up {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			deleted = append(deleted, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gw.Close()
	d := testDiscovery(t, gw.URL)
	d.resync = make(chan struct{}, 1)
	d.hostByKey["prod/web"] = "app.example.fr"

	d.deleteByKey(context.Background(), "prod/web")
	if len(d.pendingDel) != 1 {
		t.Fatalf("suppression non mémorisée : %v", d.pendingDel)
	}
	d.retryOnce(context.Background()) // toujours en panne : reste en attente
	if len(d.pendingDel) != 1 {
		t.Fatal("suppression oubliée alors que la passerelle est encore en panne")
	}

	up = true
	d.retryOnce(context.Background())
	if len(d.pendingDel) != 0 || len(deleted) != 1 || deleted[0] != "/internal/v1/routes/docker-host:app.example.fr" {
		t.Fatalf("rejeu : pending=%v supprimé=%v", d.pendingDel, deleted)
	}

	// La ressource revient avant le rejeu : la suppression en attente est annulée.
	up = false
	d.hostByKey["prod/web"] = "app.example.fr"
	d.deleteByKey(context.Background(), "prod/web")
	up = true
	d.pushRoute(context.Background(), "prod/web", map[string]string{"goproxify.backend": "http://web:80"}, "app.example.fr", "http://web:80", false)
	if len(d.pendingDel) != 0 {
		t.Fatalf("suppression périmée conservée : %v", d.pendingDel)
	}
}
