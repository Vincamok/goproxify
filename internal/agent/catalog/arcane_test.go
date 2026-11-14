// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const arcaneEnvs = `{"success":true,"data":[
 {"id":"0","name":"local","apiUrl":"http://localhost:3552","enabled":true},
 {"id":"1","name":"nas","apiUrl":"http://10.0.0.5:3552","enabled":true},
 {"id":"2","name":"off","apiUrl":"http://10.0.0.6:3552","enabled":false},
 {"id":"3","name":"lab","apiUrl":"http://10.0.0.7:3552","enabled":true}
],"pagination":{"totalItems":4}}`

const arcaneLocal = `{"success":true,"data":[
 {"id":"c1aaaaaaaaaaaaaaaa","names":["/web"],"state":"running",
  "labels":{"goproxify.enable":"true","goproxify.host":"web.example.com","autre":"x"},
  "ports":[{"privatePort":8080,"type":"tcp"}],
  "networkSettings":{"networks":{"z":{"ipAddress":""},"a":{"ipAddress":"172.18.0.4"}}}},
 {"id":"c2bbbbbbbbbbbbbbbb","names":["/db"],"state":"running","labels":{"goproxify.host":"db.example.com"}},
 {"id":"c3cccccccccccccccc","names":["/old"],"state":"exited",
  "labels":{"goproxify.enable":"true","goproxify.host":"old.example.com","goproxify.port":"9000"},
  "networkSettings":{"networks":{}}},
 {"id":"c4dddddddddddddddd","names":["/api"],"state":"running",
  "labels":{"goproxify.enable":"true","goproxify.host":"api.example.com","goproxify.backend":"https://api.internal:8443"}}
],"pagination":{"totalItems":4}}`

const arcaneNAS = `{"success":true,"data":[
 {"id":"n1eeeeeeeeeeeeeeee","names":["/app"],"state":"running",
  "labels":{"goproxify.enable":"true","goproxify.host":"app.example.com","goproxify.port":"80","goproxify.scheme":"https"},
  "ports":[{"privatePort":80,"publicPort":8081,"type":"tcp"},{"privatePort":53,"publicPort":53,"type":"udp"}],
  "networkSettings":{"networks":{"bridge":{"ipAddress":"172.17.0.2"}}}},
 {"id":"n2ffffffffffffffff","names":["/blog"],"state":"running",
  "labels":{"goproxify.enable":"true","goproxify.host":"blog.example.com"},
  "ports":[{"privatePort":2368,"publicPort":2368,"type":"tcp"}]},
 {"id":"n3gggggggggggggggg","names":["/ip"],"state":"running",
  "labels":{"goproxify.enable":"true","goproxify.host":"ip.example.com","goproxify.ip":"192.168.1.9"},
  "ports":[{"privatePort":80,"publicPort":8090,"type":"tcp"}]}
],"pagination":{"totalItems":3}}`

func arcaneServer(t *testing.T, labFails *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			http.Error(w, `{"success":false}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/environments":
			_, _ = io.WriteString(w, arcaneEnvs)
		case "/api/environments/0/containers":
			_, _ = io.WriteString(w, arcaneLocal)
		case "/api/environments/1/containers":
			_, _ = io.WriteString(w, arcaneNAS)
		case "/api/environments/3/containers":
			if labFails != nil && labFails.Load() {
				http.Error(w, "boom", http.StatusBadGateway)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"data":[{"id":"l1hhhhhhhhhhhhhhhh","names":["/wiki"],"state":"running",
			 "labels":{"goproxify.enable":"true","goproxify.host":"wiki.example.com"},
			 "ports":[{"privatePort":3000,"publicPort":3000,"type":"tcp"}]}],"pagination":{"totalItems":1}}`)
		default:
			t.Errorf("appel inattendu : %s", r.URL)
			http.NotFound(w, r)
		}
	}))
}

func TestArcane_ListsContainersOfEveryEnvironment(t *testing.T) {
	srv := arcaneServer(t, nil)
	defer srv.Close()
	a, err := NewArcane(ArcaneConfig{URL: srv.URL + "/", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Instance{}
	for _, i := range got {
		by[i.Key] = i
	}
	want := map[string]string{
		"0/c1aaaaaaaaaaaaaaaa": "http://172.18.0.4:8080",    // local : IP du conteneur, port applicatif
		"0/c3cccccccccccccccc": "http://old:9000",           // arrêté, sans IP : nom du conteneur
		"0/c4dddddddddddddddd": "https://api.internal:8443", // étiquette backend
		"1/n1eeeeeeeeeeeeeeee": "https://10.0.0.5:8081",     // distant : hôte de l'environnement, port publié
		"1/n2ffffffffffffffff": "http://10.0.0.5:2368",
		"1/n3gggggggggggggggg": "http://192.168.1.9:8090", // étiquette ip
		"3/l1hhhhhhhhhhhhhhhh": "http://10.0.0.7:3000",
	}
	if len(got) != len(want) {
		t.Fatalf("%d instances, attendu %d : %+v", len(got), len(want), got)
	}
	for k, be := range want {
		if by[k].Backend != be {
			t.Errorf("%s : backend %q, attendu %q", k, by[k].Backend, be)
		}
	}
	if by["0/c3cccccccccccccccc"].Inactive != "exited" || by["0/c1aaaaaaaaaaaaaaaa"].Inactive != "" {
		t.Errorf("états : %+v", got)
	}
	if n := by["1/n1eeeeeeeeeeeeeeee"].Name; n != "app (nas)" {
		t.Errorf("nom = %q", n)
	}
	if by["0/c1aaaaaaaaaaaaaaaa"].Labels["autre"] != "" || by["0/c1aaaaaaaaaaaaaaaa"].Labels["goproxify.host"] != "web.example.com" {
		t.Errorf("seules les étiquettes du préfixe sont gardées : %v", by["0/c1aaaaaaaaaaaaaaaa"].Labels)
	}
}

func TestArcane_SkipsEnvironmentsByNameOrID(t *testing.T) {
	srv := arcaneServer(t, nil)
	defer srv.Close()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "k", SkipEnvironments: []string{"NAS", "3"}})
	got, err := a.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range got {
		if !strings.HasPrefix(i.Key, "0/") {
			t.Errorf("environnement ignoré listé : %s", i.Key)
		}
	}
	if len(got) != 3 {
		t.Errorf("%d instances, attendu 3", len(got))
	}
}

// Un environnement injoignable garde ses dernières instances : ses routes ne sont pas retirées, et les autres
// environnements continuent d'être mis à jour.
func TestArcane_UnreachableEnvironmentKeepsItsLastInstances(t *testing.T) {
	var fails atomic.Bool
	srv := arcaneServer(t, &fails)
	defer srv.Close()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "k"})
	first, err := a.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fails.Store(true)
	second, err := a.List(context.Background())
	if err != nil {
		t.Fatalf("un environnement en panne ne doit pas faire échouer le listage : %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("%d instances après la panne, %d avant", len(second), len(first))
	}
}

// Le manager lui-même injoignable : erreur, donc aucune route retirée par le moteur.
func TestArcane_ManagerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "mauvaise"})
	if _, err := a.List(context.Background()); err == nil || strings.Contains(err.Error(), "mauvaise") {
		t.Fatalf("erreur attendue sans la clé d'API : %v", err)
	}
}

func TestArcane_ReadsEveryPage(t *testing.T) {
	var pages atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages.Add(1)
		switch {
		case r.URL.Path == "/api/environments":
			_, _ = io.WriteString(w, `{"data":[{"id":"1","name":"e","apiUrl":"http://10.0.0.5:3552","enabled":true}],"pagination":{"totalItems":1}}`)
		case r.URL.Query().Get("start") == "0":
			var rows []string
			for i := 0; i < arcanePageSize; i++ {
				rows = append(rows, fmt.Sprintf(`{"id":"a%d","names":["/a%d"],"state":"running","labels":{"goproxify.enable":"true","goproxify.host":"a%d.example.com"},"ports":[{"privatePort":80,"publicPort":%d,"type":"tcp"}]}`, i, i, i, 10000+i))
			}
			fmt.Fprintf(w, `{"data":[%s],"pagination":{"totalItems":%d}}`, strings.Join(rows, ","), arcanePageSize+1)
		case r.URL.Query().Get("start") == fmt.Sprint(arcanePageSize):
			_, _ = io.WriteString(w, fmt.Sprintf(`{"data":[{"id":"last","names":["/last"],"state":"running","labels":{"goproxify.enable":"true","goproxify.host":"last.example.com"},"ports":[{"privatePort":80,"publicPort":9,"type":"tcp"}]}],"pagination":{"totalItems":%d}}`, arcanePageSize+1))
		default:
			t.Errorf("page inattendue : %s", r.URL)
		}
	}))
	defer srv.Close()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "k"})
	got, err := a.List(context.Background())
	if err != nil || len(got) != arcanePageSize+1 {
		t.Fatalf("%d instances, %v", len(got), err)
	}
}

func TestNewArcane_RequiresURLAndKey(t *testing.T) {
	if _, err := NewArcane(ArcaneConfig{APIKey: "k"}); err == nil {
		t.Error("url requise")
	}
	if _, err := NewArcane(ArcaneConfig{URL: "https://arcane.example.com"}); err == nil {
		t.Error("clé d'API requise")
	}
}

func TestArcaneEnvHost(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"http://localhost:3552":  "",
		"http://127.0.0.1:3552":  "",
		"unix:///var/run/x.sock": "",
		"10.0.0.5:3552":          "10.0.0.5",
		"https://nas.lan:3552":   "nas.lan",
	} {
		if got := arcaneEnvHost(in); got != want {
			t.Errorf("arcaneEnvHost(%q) = %q, attendu %q", in, got, want)
		}
	}
}
