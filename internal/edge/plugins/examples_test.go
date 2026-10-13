// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Plugins d'exemple compilés avec TinyGo qui exercent ce que path-guard n'utilise pas : l'état (kv), l'appel réseau
// (http), les hooks de corps et le hook connect. Source, manifeste et commande de compilation : examples/plugins/<nom>.

func loadCompiled(t *testing.T, name string, edit func(*Manifest)) *Plugin {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "examples", "plugins", name)
	wasm, err := os.ReadFile(filepath.Join(dir, name+".wasm"))
	if err != nil {
		t.Skipf("module d'exemple absent : %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&m)
	}
	return load(t, m, wasm)
}

// Les copies du socle ABI doivent rester identiques à l'original : un correctif oublié dans une copie serait un
// plugin d'exemple qui lit mal son entrée.
func TestExamplesShareTheSameABI(t *testing.T) {
	root := filepath.Join("..", "..", "..", "examples", "plugins")
	want, err := os.ReadFile(filepath.Join(root, "_abi", "abi.go"))
	if err != nil {
		t.Skipf("socle absent : %v", err)
	}
	for _, name := range []string{"body-redact", "token-check", "tcp-allow", "coraza"} {
		got, err := os.ReadFile(filepath.Join(root, name, "abi.go"))
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
			t.Errorf("%s/abi.go a divergé de _abi/abi.go", name)
		}
	}
}

// ── rate-guard : gpx.kv_incr ──────────────────────────────────────────────────────────────────────────

func TestRateGuard_CountsPerClientAndRoute(t *testing.T) {
	p := loadCompiled(t, "rate-guard", nil)
	ctx := context.Background()
	call := func(host, ip string, cfg map[string]any, headers map[string][]string) Output {
		t.Helper()
		out, err := p.Call(ctx, HookRequest, RequestInput{Host: host, ClientIP: ip, Headers: headers, Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cfg := map[string]any{"limit": "3", "window_seconds": "60"}

	var seen []string
	for i := 0; i < 5; i++ {
		seen = append(seen, call("a.example.fr", "203.0.113.9", cfg, nil).Action)
	}
	if strings.Join(seen, ",") != "allow,allow,allow,deny,deny" {
		t.Fatalf("décisions = %v", seen)
	}
	if out := call("a.example.fr", "203.0.113.9", cfg, nil); out.Status != 429 {
		t.Fatalf("status = %d", out.Status)
	}
	// Un autre client, et la même adresse sur une autre route, ont leur propre compteur.
	if call("a.example.fr", "198.51.100.1", cfg, nil).Action != ActionAllow {
		t.Error("un autre client ne doit pas être limité")
	}
	if call("b.example.fr", "203.0.113.9", cfg, nil).Action != ActionAllow {
		t.Error("une autre route ne partage pas le compteur")
	}
}

func TestRateGuard_KeyHeaderAndNumericConfig(t *testing.T) {
	p := loadCompiled(t, "rate-guard", nil)
	ctx := context.Background()
	cfg := map[string]any{"limit": 2, "key_header": "X-Api-Key"} // entier JSON, pas une chaîne
	call := func(ip, key string) string {
		h := map[string][]string{"X-Api-Key": {key}}
		out, err := p.Call(ctx, HookRequest, RequestInput{Host: "h", ClientIP: ip, Headers: h, Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		return out.Action
	}
	// Même clé depuis deux adresses : un seul compteur ; une autre clé depuis la même adresse : un autre compteur.
	got := []string{call("1.1.1.1", "k1"), call("2.2.2.2", "k1"), call("3.3.3.3", "k1"), call("1.1.1.1", "k2")}
	if strings.Join(got, ",") != "allow,allow,deny,allow" {
		t.Fatalf("décisions = %v", got)
	}
}

func TestRateGuard_LongKeyDoesNotBreakTheHostCall(t *testing.T) {
	p := loadCompiled(t, "rate-guard", nil)
	long := strings.Repeat("x", 5000)
	for i := 0; i < 3; i++ {
		out, err := p.Call(context.Background(), HookRequest, RequestInput{Host: long, ClientIP: "1.2.3.4", Config: map[string]any{"limit": "2"}})
		if err != nil {
			t.Fatal(err)
		}
		want := ActionAllow
		if i == 2 {
			want = ActionDeny
		}
		if out.Action != want {
			t.Fatalf("appel %d : %s, attendu %s (clé tronquée à la borne de l'hôte)", i, out.Action, want)
		}
	}
}

// ── body-redact : response_body ───────────────────────────────────────────────────────────────────────

func redact(t *testing.T, p *Plugin, body string, cfg map[string]any) (Output, string) {
	t.Helper()
	out, err := p.Call(context.Background(), HookResponseBody, ResponseBodyInput{
		ResponseInput: ResponseInput{RequestInput: RequestInput{Host: "h", Path: "/", Config: cfg}, Status: 200},
		Body:          []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ReplaceBody == nil {
		return out, ""
	}
	return out, string(*out.ReplaceBody)
}

func TestBodyRedact_ReplacesEveryOccurrence(t *testing.T) {
	p := loadCompiled(t, "body-redact", nil)
	out, got := redact(t, p, `{"token":"s3cr3t","again":"s3cr3t","ok":1}`, map[string]any{"needle": "s3cr3t"})
	if out.Action != ActionModify || got != `{"token":"***","again":"***","ok":1}` {
		t.Fatalf("out=%+v corps=%q", out, got)
	}
	_, got = redact(t, p, "a-SECRET-b", map[string]any{"needle": "SECRET", "replacement": "[masqué]"})
	if got != "a-[masqué]-b" {
		t.Fatalf("remplacement configuré : %q", got)
	}
	_, got = redact(t, p, "a-SECRET-b", map[string]any{"needle": "SECRET", "replacement": ""})
	if got != "a--b" {
		t.Fatalf("remplacement vide : %q", got)
	}
}

func TestBodyRedact_LeavesBodyAloneWhenNothingToChange(t *testing.T) {
	p := loadCompiled(t, "body-redact", nil)
	for name, tc := range map[string]struct {
		body string
		cfg  map[string]any
	}{
		"texte absent":     {"rien à voir", map[string]any{"needle": "SECRET"}},
		"texte non défini": {"SECRET", map[string]any{}},
		"texte vide":       {"SECRET", map[string]any{"needle": ""}},
		"corps vide":       {"", map[string]any{"needle": "SECRET"}},
	} {
		out, _ := redact(t, p, tc.body, tc.cfg)
		if out.Action != ActionAllow || out.ReplaceBody != nil {
			t.Errorf("%s : %+v", name, out)
		}
	}
}

func TestBodyRedact_BinaryAndLargeBodies(t *testing.T) {
	p := loadCompiled(t, "body-redact", nil)
	// Octets quelconques autour du texte : le remplacement ne doit rien altérer d'autre.
	bin := append(append([]byte{0x00, 0xff, 0xfe}, []byte("SECRET")...), 0x80, 0x00)
	out, err := p.Call(context.Background(), HookResponseBody, ResponseBodyInput{
		ResponseInput: ResponseInput{RequestInput: RequestInput{Config: map[string]any{"needle": "SECRET"}}, Status: 200}, Body: bin,
	})
	if err != nil || out.ReplaceBody == nil || !bytes.Equal(*out.ReplaceBody, append(append([]byte{0x00, 0xff, 0xfe}, []byte("***")...), 0x80, 0x00)) {
		t.Fatalf("octets binaires : %+v %v", out, err)
	}
	// Un corps de 200 Kio (sous max_body_bytes) : mémoire et temps de l'appel tiennent dans les limites du manifeste.
	// Le moteur compilé (amd64, arm64) le fait en quelques dizaines de millisecondes ; l'interpréteur des autres
	// architectures est environ vingt fois plus lent, d'où un corps plus petit.
	repeat := 11000
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		repeat = 700
	}
	big := strings.Repeat("0123456789 SECRET ", repeat)
	out, got := redact(t, p, big, map[string]any{"needle": "SECRET"})
	if out.Action != ActionModify || strings.Contains(got, "SECRET") || !strings.Contains(got, "***") || len(got) != len(big)-3*repeat {
		t.Fatalf("grand corps : action=%s len=%d", out.Action, len(got))
	}
}

// ── token-check : gpx.http_fetch ──────────────────────────────────────────────────────────────────────

type authServer struct {
	*httptest.Server
	mu   sync.Mutex
	keys []string
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	a := &authServer{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		a.mu.Lock()
		a.keys = append(a.keys, key)
		a.mu.Unlock()
		switch key {
		case "bonne-cle", "a&b=c#d é", "😀<x>\"y":
			w.WriteHeader(http.StatusOK)
		case "cle-refusee":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func tokenCheck(t *testing.T, srv *authServer) (*Plugin, map[string]any) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	p := loadCompiled(t, "token-check", func(m *Manifest) {
		m.Capabilities = &Capabilities{HTTP: []string{u.Hostname()}, HTTPAllowPrivate: true}
	})
	return p, map[string]any{"auth_url": srv.URL + "/verify"}
}

func checkKey(t *testing.T, p *Plugin, cfg map[string]any, headers map[string][]string) Output {
	t.Helper()
	out, err := p.Call(context.Background(), HookRequest, RequestInput{Host: "h", Path: "/", ClientIP: "1.2.3.4", Headers: headers, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTokenCheck_DecidesFromTheAuthService(t *testing.T) {
	srv := newAuthServer(t)
	p, cfg := tokenCheck(t, srv)
	key := func(k string) map[string][]string { return map[string][]string{"X-Api-Key": {k}} }

	if out := checkKey(t, p, cfg, key("bonne-cle")); out.Action != ActionAllow {
		t.Fatalf("clé valide : %+v", out)
	}
	if out := checkKey(t, p, cfg, key("cle-refusee")); out.Action != ActionDeny || out.Status != 401 {
		t.Fatalf("clé refusée : %+v", out)
	}
	if out := checkKey(t, p, cfg, key("autre")); out.Action != ActionDeny || out.Status != 503 {
		t.Fatalf("erreur du service : %+v", out)
	}
	if out := checkKey(t, p, cfg, nil); out.Action != ActionDeny || out.Status != 401 {
		t.Fatalf("clé absente : %+v", out)
	}
	if out := checkKey(t, p, map[string]any{}, key("bonne-cle")); out.Action != ActionDeny || out.Status != 503 {
		t.Fatalf("service non configuré : %+v", out)
	}
	srv.mu.Lock()
	calls := len(srv.keys)
	srv.mu.Unlock()
	if calls != 3 {
		t.Errorf("%d appels au service, attendu 3 (aucun sans clé ni sans configuration)", calls)
	}
}

func TestTokenCheck_KeyIsEscapedAndHeaderCannotBeForged(t *testing.T) {
	srv := newAuthServer(t)
	p, cfg := tokenCheck(t, srv)

	// Une clé qui contient « & », « = » et « # » arrive intacte : elle ne peut pas ajouter de paramètre à la requête.
	// L'hôte écrit « & » et « < » en & et < dans le JSON, et un caractère hors du plan de base en paire de
	// substitution : le plugin doit les décoder, sinon la clé change avant même d'être envoyée.
	for _, k := range []string{"a&b=c#d é", "😀<x>\"y"} {
		if out := checkKey(t, p, cfg, map[string][]string{"X-Api-Key": {k}}); out.Action != ActionAllow {
			t.Fatalf("clé %q : %+v", k, out)
		}
		srv.mu.Lock()
		got := srv.keys[len(srv.keys)-1]
		srv.mu.Unlock()
		if got != k {
			t.Fatalf("le service a reçu %q, attendu %q", got, k)
		}
	}

	// Un autre en-tête dont la valeur imite le JSON d'un en-tête X-Api-Key ne doit pas passer pour la clé.
	forged := map[string][]string{"X-Other": {`"],"X-Api-Key":["bonne-cle`}}
	if out := checkKey(t, p, cfg, forged); out.Action != ActionDeny || out.Status != 401 {
		t.Fatalf("en-tête forgé : %+v", out)
	}
}

func TestTokenCheck_UnreachableServiceDeniesAndUndeclaredHostIsRefused(t *testing.T) {
	srv := newAuthServer(t)
	p, cfg := tokenCheck(t, srv)
	srv.Close()
	if out := checkKey(t, p, cfg, map[string][]string{"X-Api-Key": {"bonne-cle"}}); out.Action != ActionDeny || out.Status != 503 {
		t.Fatalf("service injoignable : %+v", out)
	}

	live := newAuthServer(t)
	p2, _ := tokenCheck(t, live)
	// Hôte absent de capabilities.http : l'hôte refuse l'appel, le plugin le traduit en 503, pas en passage libre.
	elsewhere := map[string]any{"auth_url": "http://metadata.invalid/verify"}
	if out := checkKey(t, p2, elsewhere, map[string][]string{"X-Api-Key": {"bonne-cle"}}); out.Action != ActionDeny {
		t.Fatalf("hôte non déclaré : %+v", out)
	}
}

// ── tcp-allow : connect ───────────────────────────────────────────────────────────────────────────────

func TestTCPAllow_PrefixesAndFailClosed(t *testing.T) {
	p := loadCompiled(t, "tcp-allow", nil)
	decide := func(ip string, allow any) string {
		cfg := map[string]any{}
		if allow != nil {
			cfg["allow"] = allow
		}
		out, err := p.Call(context.Background(), HookConnect, ConnectInput{ClientIP: ip, Protocol: "tcp", ListenPort: 5432, RouteID: "r", Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		return out.Action
	}
	for _, tc := range []struct {
		ip    string
		allow any
		want  string
	}{
		{"10.1.2.3", "10.,192.168.1.", ActionAllow},
		{"192.168.1.40", "10.,192.168.1.", ActionAllow},
		{"192.168.2.40", "10.,192.168.1.", ActionDeny},
		{"203.0.113.9", "10.,192.168.1.", ActionDeny},
		{"2001:db8::7", "2001:db8:", ActionAllow},
		{"2001:db9::7", "2001:db8:", ActionDeny},
		{"10.1.2.3", " 10. , ", ActionAllow}, // espaces et élément vide ignorés
		{"10.1.2.3", "", ActionDeny},         // sans préfixe : fermé
		{"10.1.2.3", nil, ActionDeny},        // sans configuration : fermé
		{"", "10.", ActionDeny},              // sans adresse : fermé
	} {
		if got := decide(tc.ip, tc.allow); got != tc.want {
			t.Errorf("ip=%q allow=%v : %s, attendu %s", tc.ip, tc.allow, got, tc.want)
		}
	}
}

// ── coût d'un appel ───────────────────────────────────────────────────────────────────────────────────

func BenchmarkExamplePlugins(b *testing.B) {
	t := &testing.T{}
	ctx := context.Background()
	rate := loadCompiled(t, "rate-guard", nil)
	redactP := loadCompiled(t, "body-redact", nil)
	tcp := loadCompiled(t, "tcp-allow", nil)
	body := []byte(strings.Repeat("0123456789 SECRET ", 200))
	_ = base64.StdEncoding

	b.Run("rate-guard", func(b *testing.B) {
		in := RequestInput{Host: "h", ClientIP: "203.0.113.9", Config: map[string]any{"limit": "1000000000"}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := rate.Call(ctx, HookRequest, in); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("body-redact-3Kio", func(b *testing.B) {
		in := ResponseBodyInput{ResponseInput: ResponseInput{RequestInput: RequestInput{Config: map[string]any{"needle": "SECRET"}}, Status: 200}, Body: body}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := redactP.Call(ctx, HookResponseBody, in); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("tcp-allow", func(b *testing.B) {
		in := ConnectInput{ClientIP: "10.1.2.3", Protocol: "tcp", Config: map[string]any{"allow": "10."}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := tcp.Call(ctx, HookConnect, in); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// ── Coraza ────────────────────────────────────────────────────────────────────────────────────────────

const corazaRules = `SecRule REQUEST_URI "@contains /etc/passwd" "id:1001,phase:1,deny,status:403,msg:'traversal'"
SecRule ARGS "@rx (?i)<script" "id:1002,phase:2,deny,status:406"
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto" "id:1003,phase:1,deny,status:403"
SecRule REQUEST_BODY "@contains DROP TABLE" "id:1004,phase:2,deny,status:403"`

func corazaCall(t *testing.T, p *Plugin, in RequestInput, body string) Output {
	t.Helper()
	in.Config = map[string]any{"rules": corazaRules}
	if in.Method == "" {
		in.Method = "GET"
	}
	if in.Headers == nil {
		in.Headers = map[string][]string{"User-Agent": {"Mozilla/5.0"}}
	}
	if body == "" {
		out, err := p.Call(context.Background(), HookRequest, in)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out, err := p.Call(context.Background(), HookRequestBody, RequestBodyInput{RequestInput: in, Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCoraza_AppliesSecLangRules(t *testing.T) {
	p := loadCompiled(t, "coraza", nil)
	base := RequestInput{Host: "app.example", Path: "/index", ClientIP: "203.0.113.9"}

	if out := corazaCall(t, p, base, ""); out.Action != ActionAllow || out.Log != "" {
		t.Fatalf("requête saine : %+v", out)
	}
	bad := base
	bad.Path = "/files/../../etc/passwd"
	if out := corazaCall(t, p, bad, ""); out.Action != ActionDeny || out.Status != 403 || !strings.Contains(out.Body, "1001") {
		t.Fatalf("chemin : %+v", out)
	}
	xss := base
	xss.Query = "q=%3Cscript%3Ealert(1)"
	if out := corazaCall(t, p, xss, ""); out.Action != ActionDeny || out.Status != 406 {
		t.Fatalf("argument : %+v", out)
	}
	ua := base
	ua.Headers = map[string][]string{"User-Agent": {"sqlmap/1.7"}}
	if out := corazaCall(t, p, ua, ""); out.Action != ActionDeny || !strings.Contains(out.Body, "1003") {
		t.Fatalf("en-tête : %+v", out)
	}
}

func TestCoraza_BodyAndMisconfiguration(t *testing.T) {
	p := loadCompiled(t, "coraza", nil)
	post := RequestInput{Method: "POST", Host: "app.example", Path: "/api", ClientIP: "203.0.113.9",
		Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}, "User-Agent": {"x"}}}
	if out := corazaCall(t, p, post, "ok=1"); out.Action != ActionAllow {
		t.Fatalf("corps sain : %+v", out)
	}
	if out := corazaCall(t, p, post, "x; DROP TABLE users"); out.Action != ActionDeny || !strings.Contains(out.Body, "1004") {
		t.Fatalf("corps : %+v", out)
	}
	for name, rules := range map[string]any{"absentes": nil, "invalides": "SecRule oups"} {
		cfg := map[string]any{}
		if rules != nil {
			cfg["rules"] = rules
		}
		out, err := p.Call(context.Background(), HookRequest, RequestInput{Path: "/etc/passwd", Config: cfg})
		if err != nil || out.Action != ActionAllow {
			t.Errorf("règles %s : %+v %v", name, out, err)
		}
	}
}

func BenchmarkCoraza(b *testing.B) {
	p := loadCompiled(&testing.T{}, "coraza", nil)
	in := RequestInput{Method: "GET", Host: "app.example", Path: "/index", Query: "a=1&b=2", ClientIP: "203.0.113.9",
		Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}}, Config: map[string]any{"rules": corazaRules}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.Call(context.Background(), HookRequest, in); err != nil {
			b.Fatal(err)
		}
	}
}
