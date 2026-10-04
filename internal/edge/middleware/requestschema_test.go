package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const orderSchema = `{"type":"object","required":["id","qty"],"properties":{"id":{"type":"string"},"qty":{"type":"integer","minimum":1}},"additionalProperties":false}`

func runSchema(t *testing.T, cfg *router.RequestSchemaConfig, method, path, ctype, body string) (code int, forwarded string, resp string) {
	t.Helper()
	h := RequestSchema("schema.example.fr", cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, forwarded, rec.Body.String()
}

func TestRequestSchemaBlock(t *testing.T) {
	cfg := &router.RequestSchemaConfig{Enabled: true, Rules: []router.RequestSchemaRule{
		{PathPrefix: "/orders", Schema: json.RawMessage(orderSchema)},
	}}
	good := `{"id":"a1","qty":2}`
	if code, fwd, _ := runSchema(t, cfg, "POST", "/orders", "application/json; charset=utf-8", good); code != 204 || fwd != good {
		t.Fatalf("valide: code=%d corps=%q", code, fwd)
	}
	code, fwd, resp := runSchema(t, cfg, "POST", "/orders", "application/json", `{"id":"a1","qty":0}`)
	if code != 422 || fwd != "" || !strings.Contains(resp, "details") || !strings.Contains(resp, "/qty") {
		t.Fatalf("invalide: code=%d fwd=%q resp=%s", code, fwd, resp)
	}
	if code, _, _ := runSchema(t, cfg, "POST", "/orders", "application/json", `{nope`); code != 422 {
		t.Fatalf("JSON cassé: %d", code)
	}
	if code, _, _ := runSchema(t, cfg, "POST", "/orders", "application/json", ``); code != 422 {
		t.Fatalf("corps vide: %d", code)
	}
	// hors règle : autre chemin, autre méthode, autre type de contenu
	for _, c := range []struct{ m, p, ct string }{
		{"POST", "/other", "application/json"}, {"GET", "/orders", "application/json"}, {"POST", "/orders", "text/plain"},
	} {
		if code, _, _ := runSchema(t, cfg, c.m, c.p, c.ct, `{"bad":true}`); code != 204 {
			t.Errorf("%v devait passer: %d", c, code)
		}
	}
	if code, _, _ := runSchema(t, cfg, "POST", "/orders", "application/vnd.api+json", `{"bad":true}`); code != 422 {
		t.Errorf("+json non validé: %d", code)
	}
}

func TestRequestSchemaDetectAndLimits(t *testing.T) {
	cfg := &router.RequestSchemaConfig{Enabled: true, Mode: "detect", MaxBody: 20, Rules: []router.RequestSchemaRule{
		{Schema: json.RawMessage(orderSchema)},
	}}
	if code, fwd, _ := runSchema(t, cfg, "POST", "/", "application/json", `{"x":1}`); code != 204 || fwd != `{"x":1}` {
		t.Fatalf("detect doit laisser passer: %d %q", code, fwd)
	}
	big := `{"id":"` + strings.Repeat("a", 40) + `","qty":1}`
	if code, fwd, _ := runSchema(t, cfg, "POST", "/", "application/json", big); code != 204 || fwd != big {
		t.Fatalf("corps trop gros en detect : le corps doit être transmis intact (%d, %d octets)", code, len(fwd))
	}
	cfg.Mode = ""
	if code, _, _ := runSchema(t, cfg, "POST", "/", "application/json", big); code != 413 {
		t.Fatalf("corps trop gros en block: %d", code)
	}
}

func TestRequestSchemaConfigValidation(t *testing.T) {
	bad := &router.RequestSchemaConfig{Enabled: true, Mode: "x", Rules: []router.RequestSchemaRule{
		{Schema: json.RawMessage(`{"type":"nope"}`)},
		{Schema: json.RawMessage(`{"$ref":"https://example.com/s.json"}`)},
	}}
	if errs := ValidateRequestSchemaConfig(bad); len(errs) < 2 {
		t.Fatalf("erreurs attendues, obtenu %v", errs)
	}
	if errs := ValidateRequestSchemaConfig(&router.RequestSchemaConfig{Enabled: true}); len(errs) == 0 {
		t.Fatal("règles requises")
	}
	if errs := ValidateRequestSchemaConfig(&router.RequestSchemaConfig{Enabled: true, Rules: []router.RequestSchemaRule{{Schema: json.RawMessage(orderSchema)}}}); len(errs) != 0 {
		t.Fatalf("config valide refusée: %v", errs)
	}
}

func TestRequestSchemaRefusesExternalRef(t *testing.T) {
	cfg := &router.RequestSchemaConfig{Enabled: true, Rules: []router.RequestSchemaRule{
		{Schema: json.RawMessage(`{"$ref":"https://example.com/s.json"}`)},
	}}
	if errs := ValidateRequestSchemaConfig(cfg); len(errs) != 1 {
		t.Fatalf("$ref externe doit être refusé : %v", errs)
	}
}
