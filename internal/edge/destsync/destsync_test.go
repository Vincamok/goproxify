// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package destsync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProxmox sert les routes de l'API Proxmox que la source lit.
func fakeProxmox(t *testing.T, auth *string) *httptest.Server {
	t.Helper()
	routes := map[string]string{
		"/api2/json/cluster/resources": `{"data":[
			{"id":"qemu/100","type":"qemu","vmid":100,"name":"web","node":"pve1","status":"running","tags":"Prod;web","pool":"front","template":0},
			{"id":"qemu/101","type":"qemu","vmid":101,"name":"tpl","node":"pve1","status":"stopped","template":1},
			{"id":"qemu/102","type":"qemu","vmid":102,"name":"cloudinit","node":"pve2","status":"stopped","tags":"prod","template":0},
			{"id":"lxc/200","type":"lxc","vmid":200,"name":"db","node":"pve1","status":"running","tags":"","pool":"back"},
			{"id":"lxc/201","type":"lxc","vmid":201,"name":"noaddr","node":"pve1","status":"running"},
			{"id":"storage/pve1/local","type":"storage","node":"pve1"}]}`,
		"/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces": `{"data":{"result":[
			{"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"}]},
			{"name":"docker0","ip-addresses":[{"ip-address":"172.17.0.1","ip-address-type":"ipv4"}]},
			{"name":"ens18","ip-addresses":[{"ip-address":"fe80::1","ip-address-type":"ipv6"},{"ip-address":"10.0.0.5","ip-address-type":"ipv4"}]}]}}`,
		"/api2/json/nodes/pve2/qemu/102/config":    `{"data":{"ipconfig0":"ip=10.0.1.9/24,gw=10.0.1.1","name":"cloudinit"}}`,
		"/api2/json/nodes/pve1/lxc/200/interfaces": `{"data":[{"name":"lo","inet":"127.0.0.1/8"},{"name":"eth0","inet":"10.0.0.20/24"}]}`,
		"/api2/json/nodes/pve1/lxc/201/config":     `{"data":{"net0":"name=eth0,bridge=vmbr0,ip=dhcp"}}`,
		"/api2/json/cluster/status":                `{"data":[{"type":"cluster","name":"lab"},{"type":"node","name":"pve1","ip":"10.0.0.1","online":1},{"type":"node","name":"pve2","ip":"10.0.0.2","online":0}]}`,
		"/api2/json/nodes/pve1/lxc/201/interfaces": `{"data":[]}`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth != nil {
			*auth = r.Header.Get("Authorization")
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			http.Error(w, "no such path", http.StatusInternalServerError) // l'agent invité absent répond ainsi
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

func proxmoxCfg(url string, extra map[string]any) map[string]any {
	cfg := map[string]any{"url": url, "token_id": "audit@pve!gpx", "token_secret": "s3cret"}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func listProxmox(t *testing.T, cfg map[string]any) []Machine {
	t.Helper()
	src, err := Build("proxmox", cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func byID(ms []Machine) map[string]Machine {
	out := map[string]Machine{}
	for _, m := range ms {
		out[m.ExternalID] = m
	}
	return out
}

func TestProxmoxListsGuestsWithTheirAddress(t *testing.T) {
	var auth string
	srv := fakeProxmox(t, &auth)
	defer srv.Close()

	got := byID(listProxmox(t, proxmoxCfg(srv.URL, map[string]any{"only_running": false})))

	if auth != "PVEAPIToken=audit@pve!gpx=s3cret" {
		t.Fatalf("en-tête d'authentification = %q", auth)
	}
	if len(got) != 4 {
		t.Fatalf("attendu 4 machines (modèle, stockage exclus), obtenu %d : %+v", len(got), got)
	}
	if m := got["qemu/100"]; m.Host != "10.0.0.5" || m.Name != "web" || !m.Running || m.Port != 22 {
		t.Fatalf("VM agent invité : %+v", m)
	} else if strings.Join(m.Tags, ",") != "prod,web" || m.Detail["node"] != "pve1" || m.Detail["pool"] != "front" {
		t.Fatalf("étiquettes ou détail : %+v", m)
	}
	if m := got["qemu/102"]; m.Host != "10.0.1.9" || m.Running {
		t.Fatalf("VM arrêtée, adresse cloud-init attendue : %+v", m)
	}
	if m := got["lxc/200"]; m.Host != "10.0.0.20" {
		t.Fatalf("conteneur LXC : %+v", m)
	}
	if m := got["lxc/201"]; m.Host != "" {
		t.Fatalf("une adresse DHCP inconnue reste vide : %+v", m)
	}
	if _, ok := got["qemu/101"]; ok {
		t.Fatal("un modèle ne doit pas être proposé")
	}
}

func TestProxmoxFilters(t *testing.T) {
	srv := fakeProxmox(t, nil)
	defer srv.Close()

	running := byID(listProxmox(t, proxmoxCfg(srv.URL, nil)))
	if _, ok := running["qemu/102"]; ok || len(running) != 3 {
		t.Fatalf("par défaut seules les machines en marche : %+v", running)
	}
	if got := listProxmox(t, proxmoxCfg(srv.URL, map[string]any{"pool": "back"})); len(got) != 1 || got[0].ExternalID != "lxc/200" {
		t.Fatalf("filtre de pool : %+v", got)
	}
	if got := listProxmox(t, proxmoxCfg(srv.URL, map[string]any{"tag": "PROD", "only_running": false})); len(got) != 2 {
		t.Fatalf("filtre d'étiquette (insensible à la casse) : %+v", got)
	}
	nodes := byID(listProxmox(t, proxmoxCfg(srv.URL, map[string]any{"include_nodes": true, "pool": "back", "ssh_port": float64(2200)})))
	if n := nodes["node/pve1"]; n.Host != "10.0.0.1" || !n.Running || n.Port != 2200 {
		t.Fatalf("nœud : %+v", n)
	}
	if n := nodes["node/pve2"]; n.Running {
		t.Fatalf("nœud hors ligne : %+v", n)
	}
}

func TestProxmoxRejectsBadConfigAndReportsAPIErrors(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"url":     {"url": "ftp://x", "token_id": "a", "token_secret": "b"},
		"secret":  {"url": "https://pve:8006", "token_id": "a"},
		"ca_cert": {"url": "https://pve:8006", "token_id": "a", "token_secret": "b", "ca_cert": "pas un pem"},
	} {
		if _, err := Build("proxmox", cfg); err == nil {
			t.Errorf("%s : configuration invalide acceptée", name)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission check failed", http.StatusUnauthorized)
	}))
	defer srv.Close()
	src, _ := Build("proxmox", proxmoxCfg(srv.URL, nil))
	_, err := src.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "PVEAuditor") {
		t.Fatalf("une erreur d'accès doit nommer le rôle requis : %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatal("le secret ne doit jamais figurer dans une erreur")
	}
}

func TestProxmoxManifestMasksTheSecret(t *testing.T) {
	man, ok := ManifestOf("proxmox")
	if !ok {
		t.Fatal("proxmox absent du registre")
	}
	masked := man.Mask(proxmoxCfg("https://pve:8006", nil))
	if masked["token_secret"] == "s3cret" {
		t.Fatal("le secret n'est pas masqué")
	}
	if err := man.Validate(proxmoxCfg("https://pve:8006", map[string]any{"inconnu": 1})); err == nil {
		t.Fatal("une clé inconnue doit être refusée")
	}
}

// --- exécuteur --------------------------------------------------------------------------------------------------------

type fakeSource struct {
	machines []Machine
	err      error
}

func (f fakeSource) List(context.Context) ([]Machine, error) { return f.machines, f.err }

type collector struct {
	mu  sync.Mutex
	got []Inventory
}

func (c *collector) add(i Inventory) { c.mu.Lock(); c.got = append(c.got, i); c.mu.Unlock() }
func (c *collector) wait(t *testing.T, n int) []Inventory {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.got) >= n {
			out := append([]Inventory(nil), c.got...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("attendu %d inventaires", n)
	return nil
}

func newTestRunner(c *collector, src Source, buildErr error) (*Runner, context.CancelFunc) {
	r := NewRunner(c.add)
	r.build = func(string, map[string]any) (Source, error) { return src, buildErr }
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	return r, cancel
}

func TestRunnerReportsACleanInventoryAndSyncNow(t *testing.T) {
	c := &collector{}
	r, stop := newTestRunner(c, fakeSource{machines: []Machine{
		{ExternalID: "b", Tags: []string{"B", "a", "a"}}, {ExternalID: "a", Name: "alpha", Port: 2200}, {ExternalID: "a"}, {ExternalID: ""},
	}}, nil)
	defer stop()

	r.Apply([]SourceConfig{{ID: "s1", Type: "fake", Enabled: true}}, true)
	inv := c.wait(t, 1)[0]
	if !inv.OK || inv.SourceID != "s1" || len(inv.Machines) != 2 {
		t.Fatalf("inventaire : %+v", inv)
	}
	if a := inv.Machines[0]; a.ExternalID != "a" || a.Port != 2200 || a.Name != "alpha" {
		t.Fatalf("tri ou doublon : %+v", inv.Machines)
	}
	if b := inv.Machines[1]; b.Port != 22 || b.Name != "b" || strings.Join(b.Tags, ",") != "a,b" {
		t.Fatalf("normalisation : %+v", b)
	}

	if !r.SyncNow("s1") {
		t.Fatal("SyncNow doit viser une source active")
	}
	c.wait(t, 2)
	if r.SyncNow("absente") {
		t.Fatal("SyncNow d'une source inconnue")
	}
}

func TestRunnerReportsFailuresWithoutMachines(t *testing.T) {
	c := &collector{}
	r, stop := newTestRunner(c, fakeSource{err: errors.New("api en panne")}, nil)
	defer stop()
	r.Apply([]SourceConfig{{ID: "s1", Type: "fake", Enabled: true}}, true)
	if inv := c.wait(t, 1)[0]; inv.OK || inv.Error != "api en panne" || len(inv.Machines) != 0 {
		t.Fatalf("un échec ne porte pas de machines : %+v", inv)
	}

	c2 := &collector{}
	r2, stop2 := newTestRunner(c2, nil, errors.New("config illisible"))
	defer stop2()
	r2.Apply([]SourceConfig{{ID: "s2", Type: "fake", Enabled: true}}, true)
	if inv := c2.wait(t, 1)[0]; inv.OK || inv.Error != "config illisible" {
		t.Fatalf("erreur de construction : %+v", inv)
	}
}

func TestRunnerRefusesATruncatedInventoryAndSurvivesAPanic(t *testing.T) {
	big := make([]Machine, maxMachines+1)
	for i := range big {
		big[i] = Machine{ExternalID: string(rune('a'+i%26)) + strings.Repeat("x", i/26)}
	}
	if _, err := cleanMachines(big); err == nil {
		t.Fatal("un inventaire démesuré doit être refusé, pas tronqué")
	}

	c := &collector{}
	r := NewRunner(c.add)
	r.build = func(string, map[string]any) (Source, error) { panic("boum") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	r.Apply([]SourceConfig{{ID: "s1", Type: "fake", Enabled: true}}, true)
	if inv := c.wait(t, 1)[0]; inv.OK || !strings.Contains(inv.Error, "boum") {
		t.Fatalf("une panique doit devenir une erreur de source : %+v", inv)
	}
}

func TestRunnerApplyStartsStopsAndSkipsDisabledOrInactive(t *testing.T) {
	c := &collector{}
	r, stop := newTestRunner(c, fakeSource{}, nil)
	defer stop()

	cfgs := []SourceConfig{{ID: "on", Type: "fake", Enabled: true}, {ID: "off", Type: "fake", Enabled: false}}
	r.Apply(cfgs, true)
	if got := strings.Join(r.Active(), ","); got != "on" {
		t.Fatalf("seule la source activée tourne : %q", got)
	}
	r.Apply(cfgs, false) // réplica en attente : le portail n'est pas ici
	if got := r.Active(); len(got) != 0 {
		t.Fatalf("inactif : aucune source ne tourne, obtenu %v", got)
	}
	r.Apply(cfgs, true)
	r.Apply(nil, true)
	if got := r.Active(); len(got) != 0 {
		t.Fatalf("source retirée de la config : %v", got)
	}
}

func TestSourceConfigInterval(t *testing.T) {
	for in, want := range map[int]int{0: DefaultInterval, -5: DefaultInterval, 10: MinInterval, 600: 600} {
		if got := (SourceConfig{IntervalS: in}).Interval(); got != want {
			t.Errorf("Interval(%d) = %d, attendu %d", in, got, want)
		}
	}
}

func TestPickIPv4PrefersPrivateAndSkipsLoopback(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"127.0.0.1", "169.254.1.1", "203.0.113.4", "192.168.1.9/24"}, "192.168.1.9"},
		{[]string{"203.0.113.4/32"}, "203.0.113.4"},
		{[]string{"::1", "fe80::1", "0.0.0.0", "pas une ip"}, ""},
	}
	for _, c := range cases {
		if got := pickIPv4(c.in); got != c.want {
			t.Errorf("pickIPv4(%v) = %q, attendu %q", c.in, got, c.want)
		}
	}
}

func TestEveryRegisteredTypeIsWellFormed(t *testing.T) {
	if len(Manifests()) == 0 {
		t.Fatal("aucun type de source enregistré")
	}
	for _, m := range Manifests() {
		for _, f := range m.Fields {
			if (strings.Contains(f.Key, "secret") || strings.Contains(f.Key, "token") || strings.Contains(f.Key, "password")) &&
				f.Kind == "password" && !f.Secret {
				t.Errorf("%s.%s : un identifiant doit être déclaré secret (ADR 0007)", m.Type, f.Key)
			}
		}
	}
}

func init() { firstPassDelay = func() time.Duration { return time.Millisecond } }
