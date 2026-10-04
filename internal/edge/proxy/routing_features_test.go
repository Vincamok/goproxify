package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestSplitWeightedStickyAndOverride(t *testing.T) {
	h := &Handler{route: &router.Route{Split: &router.SplitConfig{
		StickyCookie: "ab",
		Override:     "X-Variant",
		Variants: []router.SplitVariant{
			{Name: "a", Backend: "http://a", Weight: 50},
			{Name: "b", Backend: "http://b", Weight: 50},
			{Name: "off", Backend: "http://off", Weight: 0},
		},
	}}}

	seen := map[string]int{}
	var cookie *http.Cookie
	for i := 0; i < 400; i++ {
		rec := httptest.NewRecorder()
		seen[h.pickSplit(rec, httptest.NewRequest("GET", "/", nil))]++
		if cs := rec.Result().Cookies(); len(cs) == 1 && cs[0].Value == "b" {
			cookie = cs[0]
		}
	}
	if seen["http://a"] < 120 || seen["http://b"] < 120 || seen["http://off"] != 0 {
		t.Fatalf("répartition inattendue : %v", seen)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		if got := h.pickSplit(rec, req); got != "http://b" || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("variante mémorisée non respectée : %s", got)
		}
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Variant", "a")
	if got := h.pickSplit(httptest.NewRecorder(), req); got != "http://a" {
		t.Fatalf("override ignoré : %s", got)
	}
}

func TestSplitWithoutUsableVariant(t *testing.T) {
	h := &Handler{route: &router.Route{Split: &router.SplitConfig{Variants: []router.SplitVariant{{Name: "x", Backend: "http://x"}}}}}
	if got := h.pickSplit(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); got != "" {
		t.Fatalf("variante de poids 0 choisie : %s", got)
	}
}

func TestConditionJWTClaim(t *testing.T) {
	// Sans JWT validé par la route, la condition ne correspond jamais.
	c := router.Condition{Type: "jwt_claim", Name: "groups", Value: "beta"}
	if conditionMatches(c, nil, httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("condition vraie sans JWT")
	}
}

func TestClaimValues(t *testing.T) {
	got := claimValues([]any{"beta", true, float64(7), []any{"x"}, nil})
	if strings.Join(got, ",") != "beta,true,7,x" {
		t.Fatalf("claimValues = %v", got)
	}
}

func gzipped(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return b.Bytes()
}

func jsonResp(body []byte, enc string) *http.Response {
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	if enc != "" {
		h.Set("Content-Encoding", enc)
	}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func TestRedactJSON(t *testing.T) {
	cfg := &router.RedactConfig{Fields: []string{"password", "user.ssn", "Token"}}
	resp := jsonResp(gzipped(`{"password":"p","id":12345678901234567890,"user":{"ssn":"1","name":"n","password":"q"},"list":[{"token":"t","ok":true}],"other":{"ssn":"keep"}}`), "gzip")
	if err := applyRedactJSON(resp, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	got := string(b)
	for _, leak := range []string{`"p"`, `"q"`, `"t"`, `"1"`} {
		if strings.Contains(got, leak) {
			t.Errorf("valeur non masquée %s dans %s", leak, got)
		}
	}
	for _, keep := range []string{`12345678901234567890`, `"n"`, `"keep"`, `true`, `"***"`} {
		if !strings.Contains(got, keep) {
			t.Errorf("%s manquant dans %s", keep, got)
		}
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != int64(len(b)) {
		t.Errorf("en-têtes incohérents : %v %d", resp.Header, resp.ContentLength)
	}
}

func TestRedactJSONFailsClosed(t *testing.T) {
	cfg := &router.RedactConfig{Fields: []string{"password"}}
	if err := applyRedactJSON(jsonResp([]byte(`{"password": `), ""), cfg); err == nil {
		t.Error("JSON invalide laissé passer")
	}
	if err := applyRedactJSON(jsonResp([]byte(`{"password":"p"}`), "br"), cfg); err == nil {
		t.Error("encodage inconnu laissé passer")
	}
	text := jsonResp([]byte(`password`), "")
	text.Header.Set("Content-Type", "text/plain")
	if err := applyRedactJSON(text, cfg); err != nil {
		t.Errorf("hors JSON : %v", err)
	}
}
