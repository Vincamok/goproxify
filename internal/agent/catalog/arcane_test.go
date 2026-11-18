// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/hostaddr"
)

const arcaneEnvs = `{"success":true,"data":[
 {"id":"0","name":"local","apiUrl":"http://localhost:3552","enabled":true},
 {"id":"1","name":"nas","apiUrl":"http://10.0.0.5:3552","enabled":true},
 {"id":"2","name":"off","apiUrl":"http://10.0.0.6:3552","enabled":false},
 {"id":"3","name":"lab","apiUrl":"http://10.0.0.7:3552","enabled":true}
],"pagination":{"totalItems":4}}`

const arcaneLocal = `{"success":true,"data":[
 {"id":"c1aaaaaaaaaaaaaaaa","names":["/web"],"state":"running","image":"grafana/grafana:10.2.0",
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

// arcaneServer simule un gestionnaire Arcane 3 (collection « agents »).
func arcaneServer(t *testing.T, labFails *atomic.Bool) *httptest.Server {
	t.Helper()
	return arcaneServerOn(t, "agents", labFails)
}

// arcaneServerOn simule un gestionnaire dont la collection d'environnements est base : « agents » (Arcane 3) ou
// « environments » (Arcane 2). L'autre chemin répond 404, comme le vrai.
func arcaneServerOn(t *testing.T, base string, labFails *atomic.Bool) *httptest.Server {
	t.Helper()
	root := "/api/" + base
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			http.Error(w, `{"success":false}`, http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/agents") != (base == "agents") && strings.HasPrefix(r.URL.Path, "/api/") &&
			(strings.HasPrefix(r.URL.Path, "/api/agents") || strings.HasPrefix(r.URL.Path, "/api/environments")) {
			http.Error(w, `{"success":false,"error":"API endpoint not found"}`, http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case root:
			_, _ = io.WriteString(w, arcaneEnvs)
		case root + "/0/containers":
			_, _ = io.WriteString(w, arcaneLocal)
		case root + "/1/containers":
			_, _ = io.WriteString(w, arcaneNAS)
		case root + "/3/containers":
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
	if by["0/c1aaaaaaaaaaaaaaaa"].Image != "grafana/grafana:10.2.0" || by["1/n2ffffffffffffffff"].Image != "" {
		t.Errorf("image : %q, %q", by["0/c1aaaaaaaaaaaaaaaa"].Image, by["1/n2ffffffffffffffff"].Image)
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
		case r.URL.Path == "/api/agents":
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

// Un Arcane 2 expose ses environnements sous /environments : la source essaie /agents, reçoit 404 et retient l'ancien
// chemin, sans le réessayer à chaque sondage.
func TestArcane_FallsBackToEnvironmentsOnArcane2(t *testing.T) {
	var agentsCalls atomic.Int32
	inner := arcaneServerOn(t, "environments", nil)
	defer inner.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/agents") {
			agentsCalls.Add(1)
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer front.Close()
	a, _ := NewArcane(ArcaneConfig{URL: front.URL, APIKey: "k"})
	for i := 0; i < 2; i++ {
		got, err := a.List(context.Background())
		if err != nil || len(got) != 7 {
			t.Fatalf("passe %d : %d instances, %v", i, len(got), err)
		}
	}
	if n := agentsCalls.Load(); n != 1 {
		t.Errorf("/agents appelé %d fois, une seule attendue (le chemin appris est retenu)", n)
	}
}

// Une erreur qui n'est pas un 404 (clé refusée, panne) ne bascule pas sur l'autre chemin.
func TestArcane_OnlyNotFoundTriggersTheFallback(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "k"})
	if _, err := a.List(context.Background()); err == nil {
		t.Fatal("erreur attendue")
	}
	if calls.Load() != 1 {
		t.Errorf("%d appels, un seul attendu", calls.Load())
	}
}

func arcaneFixtureServer(t *testing.T, envAPI, ip string, publicIP ...string) *httptest.Server {
	t.Helper()
	declared := ""
	if len(publicIP) > 0 {
		declared = publicIP[0]
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agents":
			fmt.Fprintf(w, `{"data":[{"id":"e1","name":"vm-docker","apiUrl":%q,"enabled":true,"agentHost":{"publicIp":%q}}],"pagination":{"totalItems":1}}`, envAPI, declared)
		case "/api/agents/e1/containers":
			fmt.Fprintf(w, `{"data":[{"id":"c1","names":["/lore"],"state":"running","labels":{"goproxify.enable":"true","goproxify.host":"lore.example.com","goproxify.port":"80"},
			 "ports":[{"ip":%q,"privatePort":80,"publicPort":32865,"type":"tcp"}]}],"pagination":{"totalItems":1}}`, ip)
		default:
			http.NotFound(w, r)
		}
	}))
}

func arcaneBackendOf(t *testing.T, srv *httptest.Server, hosts map[string]string) string {
	t.Helper()
	a, _ := NewArcane(ArcaneConfig{URL: srv.URL, APIKey: "k", EnvironmentHosts: hosts})
	got, err := a.List(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("%d instances, %v", len(got), err)
	}
	return got[0].Backend
}

// L'adresse d'API d'un environnement peut être un nom de machine que la passerelle ne résout pas : l'adresse à laquelle
// Docker a lié le port publié, ou celle que l'opérateur impose, passent avant.
func TestArcane_BackendHostPrecedence(t *testing.T) {
	defer hostaddr.SetLookup(func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no such host") })()
	cases := map[string]struct {
		envAPI, ip string
		hosts      map[string]string
		want       string
	}{
		"hôte de l'API":              {"http://vm-docker:3552", "0.0.0.0", nil, "http://vm-docker:32865"},
		"adresse de liaison précise": {"http://vm-docker:3552", "192.168.10.91", nil, "http://192.168.10.91:32865"},
		"liaison IPv6 générique":     {"http://vm-docker:3552", "::", nil, "http://vm-docker:32865"},
		"imposée par le nom":         {"http://vm-docker:3552", "192.168.10.91", map[string]string{"VM-Docker": "10.9.9.9"}, "http://10.9.9.9:32865"},
		"imposée par l'identifiant":  {"http://vm-docker:3552", "0.0.0.0", map[string]string{"e1": "10.9.9.9"}, "http://10.9.9.9:32865"},
		"environnement local forcé":  {"http://localhost:3552", "0.0.0.0", map[string]string{"vm-docker": "10.9.9.9"}, "http://10.9.9.9:32865"},
	}
	for name, tc := range cases {
		srv := arcaneFixtureServer(t, tc.envAPI, tc.ip)
		if got := arcaneBackendOf(t, srv, tc.hosts); got != tc.want {
			t.Errorf("%s : %q, attendu %q", name, got, tc.want)
		}
		srv.Close()
	}
}

// Le nom d'hôte d'un environnement devient son adresse IP dans le backend ; un nom que l'Agent ne résout pas est gardé.
func TestArcane_EnvironmentNameBecomesAnIP(t *testing.T) {
	defer hostaddr.SetLookup(func(_ context.Context, h string) ([]net.IPAddr, error) {
		if h == "vm-docker" {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.15")}}, nil
		}
		return nil, errors.New("no such host")
	})()

	srv := arcaneFixtureServer(t, "http://vm-docker:3552", "0.0.0.0")
	defer srv.Close()
	if got := arcaneBackendOf(t, srv, nil); got != "http://10.20.0.15:32865" {
		t.Errorf("nom résolu : %q", got)
	}
	if got := arcaneBackendOf(t, srv, map[string]string{"vm-docker": "autre-nom"}); got != "http://autre-nom:32865" {
		t.Errorf("nom imposé non résolu, gardé : %q", got)
	}
	srv2 := arcaneFixtureServer(t, "http://inconnu:3552", "0.0.0.0")
	defer srv2.Close()
	if got := arcaneBackendOf(t, srv2, nil); got != "http://inconnu:32865" {
		t.Errorf("nom non résolu, gardé : %q", got)
	}
}

// L'agent Arcane de l'hôte déclare son adresse (celle du LAN) : elle remplace un nom que l'Agent ne résout pas, sans
// jamais passer avant un nom résolu ni avant une adresse imposée.
func TestArcane_UsesTheAddressDeclaredByTheArcaneAgent(t *testing.T) {
	defer hostaddr.SetLookup(func(_ context.Context, h string) ([]net.IPAddr, error) {
		if h == "resolvable" {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.99")}}, nil
		}
		return nil, errors.New("no such host")
	})()
	cases := map[string]struct {
		envAPI, public string
		hosts          map[string]string
		want           string
	}{
		"nom non résolu":                {"http://vm-docker:3552", "192.168.10.91", nil, "http://192.168.10.91:32865"},
		"nom résolu, il passe avant":    {"http://resolvable:3552", "192.168.10.91", nil, "http://10.20.0.99:32865"},
		"adresse imposée avant tout":    {"http://vm-docker:3552", "192.168.10.91", map[string]string{"vm-docker": "10.9.9.9"}, "http://10.9.9.9:32865"},
		"sans adresse d'API":            {"", "192.168.10.91", nil, "http://192.168.10.91:32865"},
		"adresse déclarée inutilisable": {"http://vm-docker:3552", "0.0.0.0", nil, "http://vm-docker:32865"},
		"adresse déclarée pas une IP":   {"http://vm-docker:3552", "hote.example.com", nil, "http://vm-docker:32865"},
	}
	for name, tc := range cases {
		srv := arcaneFixtureServer(t, tc.envAPI, "0.0.0.0", tc.public)
		if got := arcaneBackendOf(t, srv, tc.hosts); got != tc.want {
			t.Errorf("%s : %q, attendu %q", name, got, tc.want)
		}
		srv.Close()
	}
}

func arcaneNetServer(t *testing.T, extraLabels string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agents":
			_, _ = io.WriteString(w, `{"data":[{"id":"e1","name":"nas","apiUrl":"http://10.0.0.5:3552","enabled":true}],"pagination":{"totalItems":1}}`)
		case "/api/agents/e1/containers":
			fmt.Fprintf(w, `{"data":[{"id":"c1","names":["/app"],"state":"running",
			 "labels":{"goproxify.enable":"true","goproxify.host":"app.example.com"%s},
			 "ports":[{"privatePort":8080,"publicPort":32788,"type":"tcp"}],
			 "networkSettings":{"networks":{"bridge":{"ipAddress":"172.17.0.4"},"lan":{"ipAddress":"10.20.0.77"}}}}],"pagination":{"totalItems":1}}`, extraLabels)
		default:
			http.NotFound(w, r)
		}
	}))
}

func arcaneInstanceOf(t *testing.T, srv *httptest.Server, cfg ArcaneConfig) Instance {
	t.Helper()
	cfg.URL, cfg.APIKey = srv.URL, "k"
	a, err := NewArcane(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.List(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("%d instances, %v", len(got), err)
	}
	return got[0]
}

// Une adresse interne n'est proposée que si elle est sûrement joignable : jamais celle d'un bridge d'un autre hôte, qu'une
// IP identique chez la passerelle pourrait confondre avec un autre conteneur.
func TestArcane_InternalAddressOnlyWhenSurelyReachable(t *testing.T) {
	srv := arcaneNetServer(t, "")
	defer srv.Close()

	got := arcaneInstanceOf(t, srv, ArcaneConfig{})
	if got.Backend != "http://10.0.0.5:32788" || len(got.Candidates) != 0 {
		t.Errorf("hôte distant sans réseau routable : %q %v", got.Backend, got.Candidates)
	}

	got = arcaneInstanceOf(t, srv, ArcaneConfig{RoutableNetworks: []string{"10.20.0.0/16"}})
	if got.Backend != "http://10.0.0.5:32788" || len(got.Candidates) != 2 ||
		got.Candidates[0] != "http://10.20.0.77:8080" || got.Candidates[1] != "http://10.0.0.5:32788" {
		t.Errorf("réseau routable : l'IP interne et son port applicatif d'abord, le port publié ensuite : %q %v", got.Backend, got.Candidates)
	}

	var joined []string
	got = arcaneInstanceOf(t, srv, ArcaneConfig{Join: func(_ context.Context, id string, nets []string) bool {
		joined = nets
		return id == "c1"
	}})
	if got.Backend != "http://172.17.0.4:8080" || len(got.Candidates) != 0 || len(joined) != 2 {
		t.Errorf("conteneur local : IP interne servie, réseaux rejoints %v : %q %v", joined, got.Backend, got.Candidates)
	}

	got = arcaneInstanceOf(t, srv, ArcaneConfig{Join: func(context.Context, string, []string) bool { return false }})
	if got.Backend != "http://10.0.0.5:32788" || len(got.Candidates) != 0 {
		t.Errorf("conteneur non local : port publié : %q %v", got.Backend, got.Candidates)
	}
}

func TestArcane_ExplicitLabelsKeepASingleAddress(t *testing.T) {
	srv := arcaneNetServer(t, `,"goproxify.ip":"192.168.1.9"`)
	defer srv.Close()
	got := arcaneInstanceOf(t, srv, ArcaneConfig{RoutableNetworks: []string{"10.20.0.0/16"}, Join: func(context.Context, string, []string) bool { return true }})
	if got.Backend != "http://192.168.1.9:32788" || len(got.Candidates) != 0 {
		t.Errorf("l'étiquette ip désigne une seule adresse : %q %v", got.Backend, got.Candidates)
	}
}

func TestNewArcane_RejectsABadRoutableNetwork(t *testing.T) {
	if _, err := NewArcane(ArcaneConfig{URL: "https://arcane.example.com", APIKey: "k", RoutableNetworks: []string{"10.0.0.0/8", "pas-un-cidr"}}); err == nil {
		t.Error("un CIDR invalide doit être refusé")
	}
}

// Un conteneur de l'hôte de l'Agent qui publie un port est joint par l'adresse de l'hôte et ce port : toutes les passerelles
// d'un groupe HA l'atteignent. Sans adresse d'hôte connue, ou sans port publié, l'IP interne reste.
func TestArcane_LocalContainerUsesTheHostAddressAndItsPublishedPort(t *testing.T) {
	srv := arcaneNetServer(t, "")
	defer srv.Close()
	join := func(context.Context, string, []string) bool { return true }
	host := func(addr string) func(context.Context) string { return func(context.Context) string { return addr } }

	got := arcaneInstanceOf(t, srv, ArcaneConfig{Join: join, HostAddress: host("192.168.10.10")})
	if got.Backend != "http://192.168.10.10:32788" || len(got.Candidates) != 0 {
		t.Errorf("hôte connu : %q %v", got.Backend, got.Candidates)
	}
	got = arcaneInstanceOf(t, srv, ArcaneConfig{Join: join, HostAddress: host("")})
	if got.Backend != "http://172.17.0.4:8080" {
		t.Errorf("hôte inconnu : l'IP interne : %q", got.Backend)
	}
	got = arcaneInstanceOf(t, srv, ArcaneConfig{Join: join})
	if got.Backend != "http://172.17.0.4:8080" {
		t.Errorf("sans résolveur : l'IP interne : %q", got.Backend)
	}
	got = arcaneInstanceOf(t, srv, ArcaneConfig{Join: func(context.Context, string, []string) bool { return false }, HostAddress: host("192.168.10.10")})
	if got.Backend != "http://10.0.0.5:32788" {
		t.Errorf("conteneur non local : l'hôte de son environnement : %q", got.Backend)
	}
}
