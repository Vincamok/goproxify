// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

func capturingLogger() (*slog.Logger, func() string) {
	var buf bytes.Buffer
	var mu sync.Mutex
	h := slog.NewJSONHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(b)
	}), nil)
	return slog.New(h), func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

func capsManifest(c *Capabilities) Manifest {
	m := manifest()
	m.Capabilities = c
	return m
}

func loadWith(t *testing.T, m Manifest, wasm []byte, log *slog.Logger) *Plugin {
	t.Helper()
	p, err := Load(context.Background(), m, wasm, "", log)
	if err != nil {
		t.Fatalf("Load : %v", err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	return p
}

// ── gpx.kv_* ─────────────────────────────────────────────────────────────────────────────────────────

// Un plugin à état : une limitation de débit écrite avec gpx.kv_incr. L'état survit d'un appel à l'autre
// alors que chaque appel a une instance neuve.
func TestKV_RateLimiterKeepsStateAcrossCalls(t *testing.T) {
	p := loadWith(t, capsManifest(&Capabilities{KV: true}), pt.KVLimiter(3), nil)
	var got []string
	for i := 0; i < 5; i++ {
		out, err := p.Call(context.Background(), HookRequest, RequestInput{})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, out.Action)
	}
	if strings.Join(got, ",") != "allow,allow,allow,deny,deny" {
		t.Fatalf("décisions = %v", got)
	}
	out, _ := p.Call(context.Background(), HookRequest, RequestInput{})
	if out.Status != 429 {
		t.Errorf("status = %d", out.Status)
	}
}

// L'état est propre à chaque plugin chargé : un autre plugin, ou le même rechargé, repart de zéro.
func TestKV_StateIsPerPluginAndResetOnReload(t *testing.T) {
	m := capsManifest(&Capabilities{KV: true})
	a := loadWith(t, m, pt.KVLimiter(1), nil)
	b := loadWith(t, m, pt.KVLimiter(1), nil)
	call := func(p *Plugin) string {
		out, err := p.Call(context.Background(), HookRequest, RequestInput{})
		if err != nil {
			t.Fatal(err)
		}
		return out.Action
	}
	call(a)
	if call(a) != ActionDeny {
		t.Error("a devrait refuser au deuxième appel")
	}
	if call(b) != ActionAllow {
		t.Error("b ne partage pas l'état de a")
	}
	a2 := loadWith(t, m, pt.KVLimiter(1), nil)
	if call(a2) != ActionAllow {
		t.Error("un plugin rechargé repart de zéro")
	}
}

func TestKV_SetGetRoundTrip(t *testing.T) {
	p := loadWith(t, capsManifest(&Capabilities{KV: true}), pt.KVRoundTrip(`{"action":"deny","status":418}`), nil)
	out, err := p.Call(context.Background(), HookRequest, RequestInput{})
	if err != nil || out.Action != ActionDeny || out.Status != 418 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

// Sans la capacité, le module n'est pas chargé : l'import des fonctions d'état est refusé.
func TestCapabilities_ImportsRequireDeclaration(t *testing.T) {
	ctx := context.Background()
	if _, err := Load(ctx, manifest(), pt.KVLimiter(1), "", nil); err == nil || !strings.Contains(err.Error(), "import non autorisé") {
		t.Errorf("kv sans capacité : %v", err)
	}
	if _, err := Load(ctx, manifest(), pt.Fetch(`{}`), "", nil); err == nil || !strings.Contains(err.Error(), "import non autorisé") {
		t.Errorf("http sans capacité : %v", err)
	}
	// Un plugin qui déclare kv n'obtient pas http pour autant.
	if _, err := Load(ctx, capsManifest(&Capabilities{KV: true}), pt.Fetch(`{}`), "", nil); err == nil {
		t.Error("http accepté avec la seule capacité kv")
	}
}

func TestKVStore_Bounds(t *testing.T) {
	now := time.Now()
	k := newKV()
	k.nowF = func() time.Time { return now }
	// Expiration.
	if k.set("a", []byte("1"), time.Second) != 0 {
		t.Fatal("set")
	}
	if v, ok := k.get("a"); !ok || string(v) != "1" {
		t.Fatalf("get = %q %v", v, ok)
	}
	now = now.Add(2 * time.Second)
	if _, ok := k.get("a"); ok {
		t.Error("entrée expirée toujours lisible")
	}
	// Quota de clés : les expirées sont purgées avant de refuser.
	for i := 0; i < kvMaxKeys; i++ {
		if k.set(fmt.Sprintf("k%d", i), []byte("v"), time.Minute) != 0 {
			t.Fatalf("set %d refusé trop tôt", i)
		}
	}
	if k.set("trop", []byte("v"), time.Minute) != 1 {
		t.Error("le quota de clés n'est pas appliqué")
	}
	if k.set("k0", []byte("remplace"), time.Minute) != 0 {
		t.Error("remplacer une clé existante doit rester possible")
	}
	now = now.Add(2 * time.Minute)
	if k.set("apres-expiration", []byte("v"), time.Minute) != 0 {
		t.Error("les clés expirées doivent être purgées pour faire de la place")
	}
	// Compteur : fenêtre fixe, non prolongée par les incrémentations.
	if n, ok := k.incr("c", 1, time.Minute); !ok || n != 1 {
		t.Fatalf("incr = %d %v", n, ok)
	}
	now = now.Add(30 * time.Second)
	if n, _ := k.incr("c", 2, time.Minute); n != 3 {
		t.Errorf("incr = %d", n)
	}
	now = now.Add(31 * time.Second)
	if n, _ := k.incr("c", 1, time.Minute); n != 1 {
		t.Errorf("après la fenêtre, incr = %d (attendu 1)", n)
	}
	// Une valeur non numérique n'est pas un compteur.
	k.set("texte", []byte("abc"), time.Minute)
	if _, ok := k.incr("texte", 1, time.Minute); ok {
		t.Error("incr sur une valeur texte accepté")
	}
	// Un compteur se relit en décimal.
	if v, ok := k.get("c"); !ok || string(v) != "1" {
		t.Errorf("get d'un compteur = %q", v)
	}
	if ttlOf(0) != kvDefaultTTL || ttlOf(1<<31) != kvMaxTTL {
		t.Errorf("TTL par défaut/plafond : %v %v", ttlOf(0), ttlOf(1<<31))
	}
}

// ── gpx.http_fetch ───────────────────────────────────────────────────────────────────────────────────

func fetchLogged(t *testing.T, caps *Capabilities, request string, timeoutMs int) string {
	t.Helper()
	log, logged := capturingLogger()
	m := capsManifest(caps)
	m.Limits.TimeoutMs = timeoutMs
	p := loadWith(t, m, pt.Fetch(request), log)
	if _, err := p.Call(context.Background(), HookRequest, RequestInput{}); err != nil {
		t.Fatalf("Call : %v", err)
	}
	var line struct {
		Message string `json:"message"`
	}
	for _, l := range strings.Split(logged(), "\n") {
		if strings.Contains(l, `"message"`) {
			_ = json.Unmarshal([]byte(l), &line)
		}
	}
	return line.Message
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	return u.Hostname()
}

func TestFetch_AllowedHostAndPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen", r.Header.Get("X-In"))
		_, _ = io.WriteString(w, "bonjour")
	}))
	defer srv.Close()
	req := fmt.Sprintf(`{"method":"GET","url":%q,"headers":{"X-In":"abc"}}`, srv.URL)

	// Hôte autorisé mais adresse locale : refusée tant que http_allow_private n'est pas déclaré.
	got := fetchLogged(t, &Capabilities{HTTP: []string{hostOf(t, srv)}}, req, 500)
	if !strings.Contains(got, "réseau interne") || strings.Contains(got, "bonjour") {
		t.Errorf("adresse locale : %s", got)
	}
	// Avec http_allow_private, la réponse arrive : statut, en-têtes, corps (base64 : « bonjour »).
	got = fetchLogged(t, &Capabilities{HTTP: []string{hostOf(t, srv)}, HTTPAllowPrivate: true}, req, 500)
	var resp struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    []byte            `json:"body"`
		Error   string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("réponse = %q", got)
	}
	if resp.Status != 200 || string(resp.Body) != "bonjour" || resp.Headers["X-Seen"] != "abc" || resp.Error != "" {
		t.Errorf("réponse = %+v", resp)
	}
}

func TestFetch_Refusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lent" {
			time.Sleep(600 * time.Millisecond)
		}
		if r.URL.Path == "/redirige" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	caps := &Capabilities{HTTP: []string{hostOf(t, srv)}, HTTPAllowPrivate: true}
	status := func(request string) (int, string) {
		got := fetchLogged(t, caps, request, 300)
		var r struct {
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal([]byte(got), &r)
		return r.Status, r.Error
	}
	if _, e := status(`{"url":"http://autre.example.test/"}`); !strings.Contains(e, "non autorisé") {
		t.Errorf("hôte hors manifeste : %q", e)
	}
	if _, e := status(`{"url":"file:///etc/passwd"}`); !strings.Contains(e, "invalide") {
		t.Errorf("schéma : %q", e)
	}
	if _, e := status(fmt.Sprintf(`{"method":"TRACE","url":%q}`, srv.URL)); !strings.Contains(e, "méthode") {
		t.Errorf("méthode : %q", e)
	}
	if _, e := status(fmt.Sprintf(`{"url":%q,"headers":{"X-A":"v\r\nX-B: 1"}}`, srv.URL)); !strings.Contains(e, "en-tête") {
		t.Errorf("injection d'en-tête : %q", e)
	}
	// Une redirection n'est pas suivie : le plugin voit le 302, pas la cible (ici les métadonnées cloud).
	if s, _ := status(fmt.Sprintf(`{"url":%q}`, srv.URL+"/redirige")); s != http.StatusFound {
		t.Errorf("redirection suivie : statut %d", s)
	}
	// Le délai de l'appel borne aussi le réseau.
	if _, e := status(fmt.Sprintf(`{"url":%q}`, srv.URL+"/lent")); e == "" {
		t.Error("requête lente non interrompue")
	}
}

func TestCapabilities_Validation(t *testing.T) {
	for name, c := range map[string]*Capabilities{
		"hôte avec schéma":   {HTTP: []string{"https://api.example.com"}},
		"hôte avec port":     {HTTP: []string{"api.example.com:8443"}},
		"joker seul":         {HTTP: []string{"*"}},
		"joker au milieu":    {HTTP: []string{"api.*.example.com"}},
		"doublon":            {HTTP: []string{"a.example.com", "A.example.com"}},
		"private sans hôtes": {HTTPAllowPrivate: true},
	} {
		m := manifest()
		m.Capabilities = c
		if err := m.Normalize(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	m := manifest()
	m.Capabilities = &Capabilities{KV: true, HTTP: []string{"api.example.com", "*.cdn.example.com"}}
	if err := m.Normalize(); err != nil {
		t.Errorf("manifeste valide refusé : %v", err)
	}
	c := m.Capabilities
	for host, want := range map[string]bool{
		"api.example.com": true, "API.example.com.": true, "x.cdn.example.com": true, "a.b.cdn.example.com": true,
		"cdn.example.com": false, "evilcdn.example.com": false, "autre.com": false,
	} {
		if c.allowsHost(host) != want {
			t.Errorf("allowsHost(%q) = %v", host, !want)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "172.16.5.5": true, "169.254.169.254": true,
		"100.64.0.1": true, "0.0.0.0": true, "::1": true, "fe80::1": true, "fc00::1": true, "224.0.0.1": true,
		"8.8.8.8": false, "203.0.113.5": false, "2001:4860:4860::8888": false,
	} {
		if got := blockedIP(parseIP(ip)); got != want {
			t.Errorf("blockedIP(%s) = %v", ip, got)
		}
	}
}

func parseIP(s string) net.IP { return net.ParseIP(s) }
