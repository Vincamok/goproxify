package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(r.URL.RawQuery))
})

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMaintenance(t *testing.T) {
	h := Maintenance(&router.MaintenanceConfig{
		Enabled: true, RetryAfterSec: 60, BypassCIDRs: []string{"10.0.0.0/8"}, BypassHeader: "X-Team: yes",
	})(okHandler)

	rec := do(h, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("code=%d retry=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Team", "yes")
	if do(h, req).Code != 200 {
		t.Fatal("bypass par en-tête refusé")
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	if do(h, req).Code != 200 {
		t.Fatal("bypass par CIDR refusé")
	}
	if Maintenance(&router.MaintenanceConfig{Enabled: false})(okHandler) == nil {
		t.Fatal("handler nil")
	}
}

func TestSignedURL(t *testing.T) {
	cfg := &router.SignedURLConfig{Enabled: true, Secret: "s3cret"}
	h := SignedURL(cfg)(okHandler)
	exp := time.Now().Add(time.Hour).Unix()
	sig := SignURL("s3cret", "/file.zip", exp)
	target := func(path, sig string, exp int64) string {
		return path + "?a=1&sig=" + sig + "&expires=" + strconv.FormatInt(exp, 10)
	}

	rec := do(h, httptest.NewRequest("GET", target("/file.zip", sig, exp), nil))
	if rec.Code != 200 || rec.Body.String() != "a=1" {
		t.Fatalf("valide refusée ou paramètres non retirés : %d %q", rec.Code, rec.Body.String())
	}
	for name, u := range map[string]string{
		"autre chemin":   target("/other.zip", sig, exp),
		"expirée":        target("/file.zip", SignURL("s3cret", "/file.zip", exp-7200), exp-7200),
		"mauvais secret": target("/file.zip", SignURL("x", "/file.zip", exp), exp),
		"absente":        "/file.zip",
	} {
		if c := do(h, httptest.NewRequest("GET", u, nil)).Code; c != 403 {
			t.Errorf("%s : code %d", name, c)
		}
	}
	cfg.Paths = []string{"/private/"}
	if do(SignedURL(cfg)(okHandler), httptest.NewRequest("GET", "/public", nil)).Code != 200 {
		t.Fatal("chemin hors périmètre bloqué")
	}
}

func TestGraphQLLimits(t *testing.T) {
	cfg := &router.GraphQLConfig{Enabled: true, MaxDepth: 3, MaxAliases: 2, BlockIntrospection: true}
	h := GraphQLLimits(cfg)(okHandler)
	post := func(q string) int {
		body := `{"query":` + jsonString(q) + `}`
		return do(h, httptest.NewRequest("POST", "/graphql", strings.NewReader(body))).Code
	}
	cases := []struct {
		name, q string
		want    int
	}{
		{"simple", `{ user(id: "{{{") { name } }`, 200},
		{"profondeur 3", `{ a { b { c } } }`, 200},
		{"profondeur 4", `{ a { b { c { d } } } }`, 400},
		{"accolades en argument ignorées", `{ a(filter: {x: {y: {z: 1}}}) { b } }`, 200},
		{"commentaire ignoré", "{ a # { { { {\n }", 200},
		{"alias", `{ x: a y: a z: a }`, 400},
		{"introspection", `{ __schema { types { name } } }`, 400},
	}
	for _, c := range cases {
		if got := post(c.q); got != c.want {
			t.Errorf("%s : code %d, attendu %d", c.name, got, c.want)
		}
	}
	rec := do(h, httptest.NewRequest("GET", "/graphql?query="+"%7Ba%7Bb%7Bc%7Bd%7D%7D%7D%7D", nil))
	if rec.Code != 400 {
		t.Fatalf("GET profond : %d", rec.Code)
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

func TestQuotaAndHeaderKey(t *testing.T) {
	h := RateLimit(&router.RateLimitConfig{KeyBy: "header:X-Api-Key", Quota: 2, QuotaPeriod: "minute"})(okHandler)
	call := func(key string) int {
		req := httptest.NewRequest("GET", "http://quota.test/", nil)
		req.Header.Set("X-Api-Key", key)
		return do(h, req).Code
	}
	if call("k1") != 200 || call("k1") != 200 {
		t.Fatal("quota consommé trop tôt")
	}
	if call("k1") != 429 {
		t.Fatal("quota dépassé non refusé")
	}
	if call("k2") != 200 {
		t.Fatal("un autre client partage le quota")
	}
}

func TestBandwidthThrottles(t *testing.T) {
	h := Bandwidth(&router.BandwidthConfig{BytesPerSec: 20000})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 10000))
	}))
	start := time.Now()
	rec := do(h, httptest.NewRequest("GET", "/", nil))
	if rec.Body.Len() != 10000 {
		t.Fatalf("corps tronqué : %d", rec.Body.Len())
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("pas de limitation de débit (%v)", d)
	}
}

func TestSharedQuotaCountsPeers(t *testing.T) {
	cfg := &router.RateLimitConfig{KeyBy: "header:X-Api-Key", Quota: 5, QuotaPeriod: "hour", Shared: true}
	h := RateLimit(cfg)(okHandler)
	call := func() int {
		req := httptest.NewRequest("GET", "http://shared.test/", nil)
		req.Header.Set("X-Api-Key", "kk")
		return do(h, req).Code
	}
	if call() != 200 || call() != 200 {
		t.Fatal("quota consommé trop tôt")
	}
	exported := ExportQuotas()
	if len(exported) != 1 || exported[0].N != 2 {
		t.Fatalf("export = %+v", exported)
	}
	// Un pair a déjà servi 2 requêtes de la même fenêtre : il n'en reste qu'une ici.
	MergeQuotas("peer-b", []QuotaEntry{{Key: exported[0].Key, EndMs: exported[0].EndMs, N: 2}})
	MergeQuotas("peer-b", []QuotaEntry{{Key: exported[0].Key, EndMs: exported[0].EndMs, N: 1}}) // valeur plus ancienne ignorée
	if call() != 200 {
		t.Fatal("la 5e requête du groupe doit passer")
	}
	if call() != 429 {
		t.Fatal("le quota du groupe n'est pas appliqué")
	}
	if !HasSharedQuotas() {
		t.Fatal("fenêtre partagée non détectée")
	}
}
