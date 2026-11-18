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
)

// imageAPI simule l'API Kubernetes pour la recherche d'image : un Service lisible à la demande et ses pods.
type imageAPI struct {
	srv  *httptest.Server
	mu   sync.Mutex
	pods string   // réponse de la liste des pods ; vide : refusée (droit absent)
	svc  string   // réponse de GET d'un Service ; vide : refusée
	reqs []string // chemins demandés, avec la requête
}

func newImageAPI(t *testing.T, svc, pods string) *imageAPI {
	t.Helper()
	a := &imageAPI{svc: svc, pods: pods}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.reqs = append(a.reqs, r.URL.Path+"?"+r.URL.RawQuery)
		svc, pods := a.svc, a.pods
		a.mu.Unlock()
		body := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/pods"):
			body = pods
		case strings.Contains(r.URL.Path, "/services/"):
			body = svc
		}
		if body == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *imageAPI) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.reqs...)
}

func pod(annotations string, containers ...string) string {
	cs := make([]string, 0, len(containers))
	for _, c := range containers {
		name, image, _ := strings.Cut(c, "=")
		cs = append(cs, `{"name":"`+name+`","image":"`+image+`"}`)
	}
	if annotations == "" {
		annotations = "{}"
	}
	return `{"metadata":{"annotations":` + annotations + `},"spec":{"containers":[` + strings.Join(cs, ",") + `]}}`
}

func podList(pods ...string) string { return `{"items":[` + strings.Join(pods, ",") + `]}` }

func imageDiscovery(t *testing.T, api *imageAPI) *Discovery {
	d := testDiscovery(t, "http://unused")
	d.apiServer = api.srv.URL
	return d
}

var webSelector = map[string]string{"app": "web", "tier": "front"}

func TestRouteImage_MainContainerOfTheRunningPods(t *testing.T) {
	api := newImageAPI(t, "", podList(
		pod("", "app=grafana/grafana:10.2.0", "metrics=prom/statsd-exporter:v0.26.0"),
		pod("", "app=grafana/grafana:10.2.0", "metrics=prom/statsd-exporter:v0.26.0"),
	))
	d := imageDiscovery(t, api)
	got := d.routeImage(context.Background(), &serviceTarget{ns: "prod", name: "web", selector: webSelector}, nil)
	if got != "grafana/grafana:10.2.0" {
		t.Fatalf("image = %q", got)
	}
	reqs := api.requests()
	if len(reqs) != 1 || !strings.HasPrefix(reqs[0], "/api/v1/namespaces/prod/pods?") {
		t.Fatalf("requêtes = %v", reqs)
	}
	for _, want := range []string{"labelSelector=app%3Dweb%2Ctier%3Dfront", "fieldSelector=status.phase%3DRunning"} {
		if !strings.Contains(reqs[0], want) {
			t.Errorf("%q absent de %s", want, reqs[0])
		}
	}
}

func TestRouteImage_SkipsMeshSidecarsEvenWhenFirst(t *testing.T) {
	api := newImageAPI(t, "", podList(pod("", "istio-proxy=istio/proxyv2:1.20.0", "app=wordpress:6.4.2-apache")))
	got := newTestImage(t, api, &serviceTarget{ns: "prod", name: "web", selector: webSelector})
	if got != "wordpress:6.4.2-apache" {
		t.Fatalf("image = %q", got)
	}
}

func TestRouteImage_DefaultContainerAnnotationWins(t *testing.T) {
	api := newImageAPI(t, "", podList(pod(`{"kubectl.kubernetes.io/default-container":"api"}`,
		"worker=acme/worker:2.0.0", "api=acme/api:3.1.0")))
	got := newTestImage(t, api, &serviceTarget{ns: "prod", name: "web", selector: webSelector})
	if got != "acme/api:3.1.0" {
		t.Fatalf("image = %q", got)
	}
}

// Pendant une mise à jour progressive, l'image de la majorité des pods décrit ce qui sert.
func TestRouteImage_RollingUpdateTakesTheMajority(t *testing.T) {
	api := newImageAPI(t, "", podList(
		pod("", "app=acme/web:1.0.0"), pod("", "app=acme/web:1.1.0"), pod("", "app=acme/web:1.1.0"),
	))
	got := newTestImage(t, api, &serviceTarget{ns: "prod", name: "web", selector: webSelector})
	if got != "acme/web:1.1.0" {
		t.Fatalf("image = %q", got)
	}
	// À égalité, le choix est stable (ordre lexicographique), pas celui de l'ordre de la liste.
	api.mu.Lock()
	api.pods = podList(pod("", "app=acme/web:1.1.0"), pod("", "app=acme/web:1.0.0"))
	api.mu.Unlock()
	if got := newTestImage(t, api, &serviceTarget{ns: "prod", name: "web", selector: webSelector}); got != "acme/web:1.0.0" {
		t.Fatalf("égalité : image = %q", got)
	}
}

// Un Ingress ne porte pas le sélecteur : il se lit sur le Service que l'Ingress désigne.
func TestRouteImage_IngressReadsTheServiceSelector(t *testing.T) {
	api := newImageAPI(t, `{"spec":{"selector":{"app":"blog"}}}`, podList(pod("", "app=ghost:5.70.0")))
	got := newTestImage(t, api, &serviceTarget{ns: "prod", name: "blog"})
	if got != "ghost:5.70.0" {
		t.Fatalf("image = %q", got)
	}
	reqs := api.requests()
	if len(reqs) != 2 || !strings.HasPrefix(reqs[0], "/api/v1/namespaces/prod/services/blog") ||
		!strings.Contains(reqs[1], "labelSelector=app%3Dblog") {
		t.Fatalf("requêtes = %v", reqs)
	}
}

// Ne pas savoir n'est pas une erreur : pas d'image, la route est annoncée comme avant.
func TestRouteImage_UnknownGivesNoImage(t *testing.T) {
	cases := map[string]struct {
		api    *imageAPI
		target *serviceTarget
		reqs   int
	}{
		"pas de Service":      {newImageAPI(t, "", ""), nil, 0},
		"sans sélecteur":      {newImageAPI(t, "", podList(pod("", "app=x:1"))), &serviceTarget{ns: "p", name: "ext", selector: map[string]string{}}, 0},
		"Service sans sélect": {newImageAPI(t, `{"spec":{}}`, podList(pod("", "app=x:1"))), &serviceTarget{ns: "p", name: "ext"}, 1},
		"Service illisible":   {newImageAPI(t, "", podList(pod("", "app=x:1"))), &serviceTarget{ns: "p", name: "web"}, 1},
		"pods refusés":        {newImageAPI(t, "", ""), &serviceTarget{ns: "p", name: "web", selector: webSelector}, 1},
		"aucun pod en marche": {newImageAPI(t, "", podList()), &serviceTarget{ns: "p", name: "web", selector: webSelector}, 1},
	}
	for name, c := range cases {
		if got := newTestImage(t, c.api, c.target); got != "" {
			t.Errorf("%s : image = %q", name, got)
		}
		if n := len(c.api.requests()); n != c.reqs {
			t.Errorf("%s : %d requêtes (%v), attendu %d", name, n, c.api.requests(), c.reqs)
		}
	}
}

// Dans un état complet, les pods d'un Service ne sont lus qu'une fois, quel que soit le nombre de routes.
func TestRouteImage_CacheReadsPodsOnce(t *testing.T) {
	api := newImageAPI(t, "", podList(pod("", "app=acme/web:1.0.0")))
	d := imageDiscovery(t, api)
	cache := map[string]string{}
	target := &serviceTarget{ns: "prod", name: "web", selector: webSelector}
	for i := 0; i < 3; i++ {
		if got := d.routeImage(context.Background(), target, cache); got != "acme/web:1.0.0" {
			t.Fatalf("image = %q", got)
		}
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("%d requêtes, attendu 1", n)
	}
}

func newTestImage(t *testing.T, api *imageAPI, target *serviceTarget) string {
	t.Helper()
	return imageDiscovery(t, api).routeImage(context.Background(), target, nil)
}

// Un Service qui a son sélecteur donne l'image de ses pods ; une étiquette backend désigne autre chose que le Service :
// pas d'image dans ce cas.
func TestServiceRoute_TargetUnlessBackendAnnotation(t *testing.T) {
	d := testDiscovery(t, "http://unused")
	var svc k8sService
	svc.Metadata = k8sMeta{Name: "web", Namespace: "prod", Annotations: map[string]string{"goproxify.host": "web.example.fr"}}
	svc.Spec.Selector = webSelector
	r, ok := d.serviceRoute(svc)
	if !ok || r.target == nil || r.target.ns != "prod" || r.target.name != "web" || r.target.selector["app"] != "web" {
		t.Fatalf("route = %+v", r)
	}
	svc.Metadata.Annotations["goproxify.backend"] = "http://ailleurs:80"
	if r, _ := d.serviceRoute(svc); r.target != nil {
		t.Fatalf("une étiquette backend ne désigne plus le Service : %+v", r.target)
	}
}

func TestIngressRoute_TargetsTheBackendService(t *testing.T) {
	d := testDiscovery(t, "http://unused")
	ing := k8sIngress{Metadata: k8sMeta{Name: "site", Namespace: "prod", Annotations: map[string]string{}}}
	ing.Spec.Rules = []ingressRule{{Host: "site.example.fr", HTTP: &httpPaths{Paths: []ingressPath{
		{Backend: ingressBackend{Service: &ingressService{Name: "blog", Port: ingressSvcPort{Number: 2368}}}},
	}}}}
	routes := d.ingressRoutes(ing)
	if len(routes) != 1 || routes[0].target == nil || routes[0].target.ns != "prod" || routes[0].target.name != "blog" {
		t.Fatalf("routes = %+v", routes)
	}
	ing.Metadata.Annotations["goproxify.backend"] = "http://ailleurs:80"
	if routes := d.ingressRoutes(ing); len(routes) != 1 || routes[0].target != nil {
		t.Fatalf("routes = %+v", routes)
	}
}

// De bout en bout : le Service d'abord, ses pods ensuite, l'image part dans la route envoyée à la passerelle.
func TestUpsertService_ImageReachesTheGateway(t *testing.T) {
	var got map[string]any
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gw.Close()
	api := newImageAPI(t, "", podList(pod("", "app=grafana/grafana:10.2.0")))
	d := testDiscovery(t, gw.URL)
	d.apiServer = api.srv.URL

	var svc k8sService
	svc.Metadata = k8sMeta{Name: "web", Namespace: "prod", Annotations: map[string]string{"goproxify.host": "web.example.fr"}}
	svc.Spec.ClusterIP = "10.1.2.3"
	svc.Spec.Selector = webSelector
	d.upsertService(context.Background(), svc)

	if got["image"] != "grafana/grafana:10.2.0" {
		t.Fatalf("image = %v (payload %v)", got["image"], got)
	}
}
