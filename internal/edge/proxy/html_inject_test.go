// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func htmlResp(body, ct string, hdr map[string]string) *http.Response {
	r := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{Method: http.MethodGet}}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func bodyOf(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHTMLInject_PositionsAndAnchors(t *testing.T) {
	const page = "<html><head><title>x</title></head><body><script>var s='</body>';</script><p>a</p></BODY></html>"
	for name, tc := range map[string]struct {
		cfg  router.HTMLInjectConfig
		want string
	}{
		"fin du head": {router.HTMLInjectConfig{Position: router.HTMLInjectHeadEnd, Content: "<!--X-->"},
			"<html><head><title>x</title><!--X--></head><body><script>var s='</body>';</script><p>a</p></BODY></html>"},
		"fin du body (dernière balise, casse ignorée)": {router.HTMLInjectConfig{Content: "<!--X-->"},
			"<html><head><title>x</title></head><body><script>var s='</body>';</script><p>a</p><!--X--></BODY></html>"},
	} {
		resp := htmlResp(page, "text/html; charset=utf-8", nil)
		if err := applyHTMLInject(resp, &tc.cfg); err != nil {
			t.Fatal(err)
		}
		if got := bodyOf(t, resp); got != tc.want {
			t.Errorf("%s : %q", name, got)
		}
		if resp.Header.Get("Content-Length") != strconv.Itoa(len(tc.want)) || resp.ContentLength != int64(len(tc.want)) {
			t.Errorf("%s : Content-Length %q / %d", name, resp.Header.Get("Content-Length"), resp.ContentLength)
		}
	}
}

func TestHTMLInject_LeavesOtherResponsesAlone(t *testing.T) {
	cfg := &router.HTMLInjectConfig{Content: "<!--X-->"}
	for name, resp := range map[string]*http.Response{
		"texte brut":       htmlResp("</body>", "text/plain", nil),
		"JSON":             htmlResp(`{"a":"</body>"}`, "application/json", nil),
		"sans ancre":       htmlResp("<p>fragment</p>", "text/html", nil),
		"encodage inconnu": htmlResp("</body>", "text/html", map[string]string{"Content-Encoding": "br"}),
		"HEAD": func() *http.Response {
			r := htmlResp("</body>", "text/html", nil)
			r.Request.Method = http.MethodHead
			return r
		}(),
	} {
		raw, _ := io.ReadAll(resp.Body)
		want := string(raw)
		resp.Body = io.NopCloser(strings.NewReader(want))
		if err := applyHTMLInject(resp, cfg); err != nil {
			t.Fatal(err)
		}
		if got := bodyOf(t, resp); got != want {
			t.Errorf("%s : corps changé %q", name, got)
		}
	}
	// Configuration vide, trop grosse.
	for name, c := range map[string]*router.HTMLInjectConfig{"nil": nil, "vide": {}, "trop gros": {Content: strings.Repeat("x", htmlInjectMaxContent+1)}} {
		resp := htmlResp("</body>", "text/html", nil)
		if err := applyHTMLInject(resp, c); err != nil || bodyOf(t, resp) != "</body>" {
			t.Errorf("%s : %v", name, err)
		}
	}
}

func TestHTMLInject_Gzip(t *testing.T) {
	var zb bytes.Buffer
	gz := gzip.NewWriter(&zb)
	_, _ = gz.Write([]byte("<html><body>hi</body></html>"))
	gz.Close()
	resp := &http.Response{StatusCode: 200, Request: &http.Request{Method: "GET"},
		Header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}, "Etag": {`"v1"`}},
		Body:   io.NopCloser(bytes.NewReader(zb.Bytes()))}
	if err := applyHTMLInject(resp, &router.HTMLInjectConfig{Content: "<i>!</i>"}); err != nil {
		t.Fatal(err)
	}
	if got := bodyOf(t, resp); got != "<html><body>hi<i>!</i></body></html>" {
		t.Fatalf("corps : %q", got)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("ETag") != "" {
		t.Errorf("en-têtes périmés : %v", resp.Header)
	}

	// Gzip invalide : la réponse repart telle quelle, encodage compris.
	bad := &http.Response{StatusCode: 200, Request: &http.Request{Method: "GET"},
		Header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, Body: io.NopCloser(strings.NewReader("pas du gzip"))}
	if err := applyHTMLInject(bad, &router.HTMLInjectConfig{Content: "x"}); err != nil {
		t.Fatal(err)
	}
	if bodyOf(t, bad) != "pas du gzip" || bad.Header.Get("Content-Encoding") != "gzip" {
		t.Error("une réponse gzip illisible doit rester intacte")
	}
}

func TestHTMLInject_OversizedBodyIsStreamedBack(t *testing.T) {
	big := "<body>" + strings.Repeat("a", htmlInjectMaxBody) + "</body>"
	resp := htmlResp(big, "text/html", nil)
	if err := applyHTMLInject(resp, &router.HTMLInjectConfig{Content: "<!--X-->"}); err != nil {
		t.Fatal(err)
	}
	if got := bodyOf(t, resp); got != big {
		t.Fatalf("corps trop gros altéré (%d octets au lieu de %d)", len(got), len(big))
	}
}

func TestHTMLInject_CSPNonce(t *testing.T) {
	cfg := &router.HTMLInjectConfig{Content: `<script nonce="{{nonce}}">1</script>`, CSPNonce: true}
	resp := htmlResp("<body></body>", "text/html", map[string]string{"Content-Security-Policy": "default-src 'self'; script-src 'self' cdn.example; img-src *"})
	if err := applyHTMLInject(resp, cfg); err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	i := strings.Index(body, `nonce="`)
	if i < 0 || strings.Contains(body, "{{nonce}}") {
		t.Fatalf("nonce non substitué : %q", body)
	}
	nonce := body[i+7 : strings.Index(body[i+7:], `"`)+i+7]
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' cdn.example 'nonce-"+nonce+"'") || strings.Contains(csp, "default-src 'self' 'nonce") {
		t.Errorf("CSP : %q", csp)
	}

	// Sans script-src : default-src reçoit le nonce ; sans politique : rien n'est ajouté.
	r2 := htmlResp("<body></body>", "text/html", map[string]string{"Content-Security-Policy": "default-src 'self'"})
	_ = applyHTMLInject(r2, cfg)
	if !strings.Contains(r2.Header.Get("Content-Security-Policy"), "default-src 'self' 'nonce-") {
		t.Errorf("default-src : %q", r2.Header.Get("Content-Security-Policy"))
	}
	r3 := htmlResp("<body></body>", "text/html", nil)
	_ = applyHTMLInject(r3, cfg)
	if r3.Header.Get("Content-Security-Policy") != "" {
		t.Error("aucune politique ne doit être créée")
	}
	// Deux réponses : deux nonces.
	r4, r5 := htmlResp("<body></body>", "text/html", nil), htmlResp("<body></body>", "text/html", nil)
	_ = applyHTMLInject(r4, cfg)
	_ = applyHTMLInject(r5, cfg)
	if bodyOf(t, r4) == bodyOf(t, r5) {
		t.Error("le nonce doit changer à chaque réponse")
	}
}

func TestHTMLInject_EndToEndThroughTheHandler(t *testing.T) {
	var gotAE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(gotAE, "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte("<html><body>page</body></html>"))
			gz.Close()
			return
		}
		_, _ = io.WriteString(w, "<html><body>page</body></html>")
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{
		Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		HTMLInject: &router.HTMLInjectConfig{Content: "<script src=/t.js></script>"},
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Header.Set("Accept-Encoding", "br, zstd, gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if gotAE != "gzip" {
		t.Errorf("Accept-Encoding vers le backend : %q, attendu gzip seul", gotAE)
	}
	if rec.Body.String() != "<html><body>page<script src=/t.js></script></body></html>" {
		t.Errorf("corps : %q", rec.Body.String())
	}
}
