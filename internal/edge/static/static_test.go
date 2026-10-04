package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func newSite(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<h1>app</h1>")
	write("assets/app.js", "console.log(1)")
	write("docs/index.html", "<h1>docs</h1>")
	write(".env", "SECRET=1")
	return dir
}

func get(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestStaticServing(t *testing.T) {
	h := Handler(&router.StaticConfig{Enabled: true, Root: newSite(t), SPAFallback: true, CacheMaxAge: 60})

	cases := []struct {
		name, method, target string
		hdr                  []string
		code                 int
		body                 string
	}{
		{"index", "GET", "/", nil, 200, "<h1>app</h1>"},
		{"fichier", "GET", "/assets/app.js", nil, 200, "console.log(1)"},
		{"index de dossier", "GET", "/docs/", nil, 200, "<h1>docs</h1>"},
		{"repli SPA", "GET", "/users/42", nil, 200, "<h1>app</h1>"},
		{"ressource manquante", "GET", "/assets/missing.js", nil, 404, ""},
		{"ressource avec Accept html", "GET", "/old.html", []string{"Accept", "text/html"}, 200, "<h1>app</h1>"},
		{"fichier caché", "GET", "/.env", nil, 404, ""},
		{"traversée", "GET", "/../../etc/passwd", nil, 200, "<h1>app</h1>"},
		{"méthode", "POST", "/", nil, 405, ""},
	}
	for _, c := range cases {
		w := get(h, c.method, c.target, c.hdr...)
		if w.Code != c.code {
			t.Errorf("%s: code %d, attendu %d", c.name, w.Code, c.code)
		}
		if c.body != "" && w.Body.String() != c.body {
			t.Errorf("%s: corps %q", c.name, w.Body.String())
		}
	}

	if cc := get(h, "GET", "/assets/app.js").Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control assets = %q", cc)
	}
	if cc := get(h, "GET", "/").Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control index = %q", cc)
	}
	etag := get(h, "GET", "/assets/app.js").Header().Get("ETag")
	if w := get(h, "GET", "/assets/app.js", "If-None-Match", etag); w.Code != http.StatusNotModified {
		t.Errorf("revalidation = %d", w.Code)
	}
}

func TestStaticNoFallback(t *testing.T) {
	h := Handler(&router.StaticConfig{Enabled: true, Root: newSite(t)})
	if w := get(h, "GET", "/users/42"); w.Code != 404 {
		t.Errorf("sans repli SPA: %d", w.Code)
	}
}
