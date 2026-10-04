// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

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

const petSpec = `
openapi: 3.0.3
info: {title: Pets, version: "1"}
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          schema: {type: integer, minimum: 1, maximum: 100}
        - name: tag
          in: query
          schema: {type: array, items: {type: string}}
        - $ref: '#/components/parameters/TraceID'
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewPet'}
  /pets/{petId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema: {type: integer}
    get: {}
    delete: {}
  /pets/mine:
    get: {}
  /upload:
    post:
      requestBody:
        content:
          multipart/form-data: {}
components:
  parameters:
    TraceID:
      name: X-Trace-Id
      in: header
      required: true
      schema: {type: string, format: uuid}
  schemas:
    NewPet:
      type: object
      required: [name]
      additionalProperties: false
      properties:
        name: {type: string, minLength: 1}
        nickname: {type: string, nullable: true}
        age: {type: integer, minimum: 0, exclusiveMinimum: false}
        tags: {type: array, items: {$ref: '#/components/schemas/Tag'}}
    Tag:
      type: string
      enum: [cat, dog]
`

const traceOK = "6f1c0a52-9f6e-4c11-b2b6-2d8f3b3c7a11"

func runOpenAPI(t *testing.T, cfg *router.OpenAPIConfig, method, target, ctype, body string, hdr map[string]string) (code int, forwarded string, resp string, hdrs http.Header) {
	t.Helper()
	h := OpenAPI("api.example.fr", cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, forwarded, rec.Body.String(), rec.Header()
}

func petCfg(mut func(*router.OpenAPIConfig)) *router.OpenAPIConfig {
	raw, _ := json.Marshal(petSpec)
	c := &router.OpenAPIConfig{Enabled: true, Spec: raw}
	if mut != nil {
		mut(c)
	}
	return c
}

func TestOpenAPIPathParameter(t *testing.T) {
	cfg := petCfg(nil)
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/pets/42", "", "", nil); code != 204 {
		t.Fatalf("petId entier : %d", code)
	}
	code, _, resp, _ := runOpenAPI(t, cfg, "GET", "/pets/abc", "", "", nil)
	if code != 400 || !strings.Contains(resp, `"name":"petId"`) {
		t.Fatalf("petId texte : %d %s", code, resp)
	}
	// le gabarit littéral l'emporte sur le gabarit à paramètre
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/pets/mine", "", "", nil); code != 204 {
		t.Fatalf("/pets/mine doit viser le gabarit littéral : %d", code)
	}
}

func TestOpenAPIQueryAndHeaderParameters(t *testing.T) {
	cfg := petCfg(nil)
	ok := map[string]string{"X-Trace-Id": traceOK}
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/pets?limit=10&tag=a&tag=b", "", "", ok); code != 204 {
		t.Fatalf("requête valide : %d", code)
	}
	for _, c := range []struct {
		name, target string
		hdr          map[string]string
		want         string
	}{
		{"limite hors bornes", "/pets?limit=500", ok, `"name":"limit"`},
		{"limite non numérique", "/pets?limit=abc", ok, `"name":"limit"`},
		{"en-tête requis absent", "/pets?limit=1", nil, `"name":"X-Trace-Id"`},
		{"en-tête au mauvais format", "/pets", map[string]string{"X-Trace-Id": "pas-un-uuid"}, `"name":"X-Trace-Id"`},
	} {
		code, _, resp, _ := runOpenAPI(t, cfg, "GET", c.target, "", "", c.hdr)
		if code != 400 || !strings.Contains(resp, c.want) {
			t.Errorf("%s : %d %s", c.name, code, resp)
		}
	}
}

func TestOpenAPIBody(t *testing.T) {
	cfg := petCfg(nil)
	h := map[string]string{"X-Trace-Id": traceOK}
	good := `{"name":"Rex","nickname":null,"age":3,"tags":["dog"]}`
	if code, fwd, _, _ := runOpenAPI(t, cfg, "POST", "/pets", "application/json", good, h); code != 204 || fwd != good {
		t.Fatalf("corps valide (nullable 3.0 accepté) : %d %q", code, fwd)
	}
	for _, c := range []struct{ name, body, want string }{
		{"champ requis absent", `{"age":1}`, "name"},
		{"propriété inconnue", `{"name":"a","x":1}`, ""},
		{"énumération via $ref", `{"name":"a","tags":["bird"]}`, "/tags/0"},
		{"type du champ", `{"name":"a","age":"3"}`, "/age"},
		{"JSON cassé", `{nope`, ""},
	} {
		code, fwd, resp, _ := runOpenAPI(t, cfg, "POST", "/pets", "application/json", c.body, h)
		if code != 422 || fwd != "" || !strings.Contains(resp, c.want) {
			t.Errorf("%s : %d fwd=%q %s", c.name, code, fwd, resp)
		}
	}
	if code, _, resp, _ := runOpenAPI(t, cfg, "POST", "/pets", "", "", h); code != 422 || !strings.Contains(resp, "corps requis") {
		t.Errorf("corps requis absent : %d %s", code, resp)
	}
	if code, _, _, _ := runOpenAPI(t, cfg, "POST", "/pets", "text/plain", "hello", h); code != 415 {
		t.Errorf("type de contenu non déclaré : %d", code)
	}
	// un type déclaré sans schéma (multipart) traverse sans lecture
	if code, fwd, _, _ := runOpenAPI(t, cfg, "POST", "/upload", "multipart/form-data; boundary=x", "raw", nil); code != 204 || fwd != "raw" {
		t.Errorf("multipart : %d %q", code, fwd)
	}
}

func TestOpenAPIBodyTooLarge(t *testing.T) {
	cfg := petCfg(func(c *router.OpenAPIConfig) { c.MaxBody = 10 })
	big := `{"name":"` + strings.Repeat("a", 50) + `"}`
	if code, _, _, _ := runOpenAPI(t, cfg, "POST", "/pets", "application/json", big, map[string]string{"X-Trace-Id": traceOK}); code != 413 {
		t.Fatalf("corps trop gros : %d", code)
	}
}

func TestOpenAPIUnknownPathsPolicy(t *testing.T) {
	// par défaut la spécification peut être partielle : un chemin inconnu passe
	if code, _, _, _ := runOpenAPI(t, petCfg(nil), "GET", "/health", "", "", nil); code != 204 {
		t.Fatalf("chemin inconnu toléré : %d", code)
	}
	strict := petCfg(func(c *router.OpenAPIConfig) { c.UnknownPaths = "block" })
	if code, _, _, _ := runOpenAPI(t, strict, "GET", "/health", "", "", nil); code != 404 {
		t.Fatalf("chemin inconnu refusé : %d", code)
	}
	code, _, _, hdr := runOpenAPI(t, strict, "PUT", "/pets/1", "", "", nil)
	if code != 405 || hdr.Get("Allow") != "DELETE, GET" {
		t.Fatalf("méthode inconnue : %d Allow=%q", code, hdr.Get("Allow"))
	}
}

func TestOpenAPIDetectModeAndSkip(t *testing.T) {
	detect := petCfg(func(c *router.OpenAPIConfig) { c.Mode = "detect"; c.UnknownPaths = "block" })
	for _, target := range []string{"/pets/abc", "/health"} {
		if code, _, _, _ := runOpenAPI(t, detect, "GET", target, "", "", nil); code != 204 {
			t.Errorf("detect doit laisser passer %s : %d", target, code)
		}
	}
	skip := petCfg(func(c *router.OpenAPIConfig) { c.Skip = []string{"header", "path"} })
	if code, _, _, _ := runOpenAPI(t, skip, "GET", "/pets/abc", "", "", nil); code != 204 {
		t.Fatalf("path ignoré : %d", code)
	}
	if code, _, _, _ := runOpenAPI(t, skip, "GET", "/pets?limit=500", "", "", nil); code != 400 {
		t.Fatalf("query toujours contrôlée : %d", code)
	}
}

func TestOpenAPIStripPrefix(t *testing.T) {
	cfg := petCfg(func(c *router.OpenAPIConfig) { c.StripPrefix = "/api/v1"; c.UnknownPaths = "block" })
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/api/v1/pets/7", "", "", nil); code != 204 {
		t.Fatalf("préfixe retiré : %d", code)
	}
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/api/v1/pets/x", "", "", nil); code != 400 {
		t.Fatalf("paramètre contrôlé derrière le préfixe : %d", code)
	}
}

func TestOpenAPISpecAsJSONObjectAnd31(t *testing.T) {
	spec := `{"openapi":"3.1.0","paths":{"/n":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":["integer","null"],"exclusiveMinimum":0}}}}}}}}`
	cfg := &router.OpenAPIConfig{Enabled: true, Spec: json.RawMessage(spec)}
	if code, _, _, _ := runOpenAPI(t, cfg, "POST", "/n", "application/json", `5`, nil); code != 204 {
		t.Fatalf("3.1 valide : %d", code)
	}
	if code, _, _, _ := runOpenAPI(t, cfg, "POST", "/n", "application/json", `0`, nil); code != 422 {
		t.Fatalf("3.1 exclusiveMinimum numérique : %d", code)
	}
}

func TestValidateOpenAPIConfig(t *testing.T) {
	bad := func(spec string, mut func(*router.OpenAPIConfig)) []string {
		raw, _ := json.Marshal(spec)
		c := &router.OpenAPIConfig{Enabled: true, Spec: raw}
		if mut != nil {
			mut(c)
		}
		return ValidateOpenAPIConfig(c)
	}
	if errs := bad(petSpec, nil); len(errs) != 0 {
		t.Fatalf("spécification valide refusée : %v", errs)
	}
	body := func(schema string) string {
		return "openapi: 3.0.0\npaths:\n  /a:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: " + schema
	}
	for name, errs := range map[string][]string{
		"vide":            bad("", nil),
		"swagger 2":       bad("swagger: \"2.0\"\npaths: {/a: {get: {}}}", nil),
		"sans chemins":    bad("openapi: 3.0.0\npaths: {}", nil),
		"ref externe":     bad(body("{$ref: 'https://evil.example/s.json'}"), nil),
		"ref introuvable": bad(body("{$ref: '#/components/schemas/Nope'}"), nil),
		"chemin sans {}":  bad("openapi: 3.0.0\npaths:\n  /a/{id}:\n    get: {}", nil),
		"mode":            bad(petSpec, func(c *router.OpenAPIConfig) { c.Mode = "x" }),
		"unknown_paths":   bad(petSpec, func(c *router.OpenAPIConfig) { c.UnknownPaths = "x" }),
		"skip":            bad(petSpec, func(c *router.OpenAPIConfig) { c.Skip = []string{"x"} }),
		"strip_prefix":    bad(petSpec, func(c *router.OpenAPIConfig) { c.StripPrefix = "api" }),
	} {
		if len(errs) == 0 {
			t.Errorf("%s : aucune erreur", name)
		}
	}
	if errs := ValidateOpenAPIConfig(&router.OpenAPIConfig{Enabled: false}); errs != nil {
		t.Errorf("désactivé : %v", errs)
	}
}

func TestOpenAPIInvalidSpecLetsTrafficThrough(t *testing.T) {
	cfg := &router.OpenAPIConfig{Enabled: true, Spec: json.RawMessage(`"not: [valid"`)}
	if code, _, _, _ := runOpenAPI(t, cfg, "GET", "/x", "", "", nil); code != 204 {
		t.Fatalf("spécification invalide : %d", code)
	}
}
