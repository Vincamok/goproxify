package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var compressBody = strings.Repeat("goproxify ", 500)

func serveCompressed(t *testing.T, cfg *router.CompressionConfig, ae, ct string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	if h == nil {
		h = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			_, _ = io.WriteString(w, compressBody)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	if ae != "" {
		req.Header.Set("Accept-Encoding", ae)
	}
	rec := httptest.NewRecorder()
	Compress(cfg)(h).ServeHTTP(rec, req)
	return rec
}

func TestCompressNegotiation(t *testing.T) {
	cfg := &router.CompressionConfig{Enabled: true}
	cases := []struct{ ae, want string }{
		{"gzip, br, zstd", "zstd"},
		{"gzip, br", "br"},
		{"gzip", "gzip"},
		{"gzip, zstd;q=0", "gzip"},
		{"*", "zstd"},
		{"identity", ""},
		{"", ""},
	}
	for _, c := range cases {
		rec := serveCompressed(t, cfg, c.ae, "text/html", nil)
		if got := rec.Header().Get("Content-Encoding"); got != c.want {
			t.Errorf("AE=%q: got %q, want %q", c.ae, got, c.want)
		}
	}
}

func TestCompressRoundTrip(t *testing.T) {
	cfg := &router.CompressionConfig{Enabled: true, Level: 3}
	for _, enc := range []string{"gzip", "br", "zstd"} {
		rec := serveCompressed(t, cfg, enc, "application/json", nil)
		if rec.Header().Get("Content-Encoding") != enc {
			t.Fatalf("%s: encoding %q", enc, rec.Header().Get("Content-Encoding"))
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: Vary manquant", enc)
		}
		var r io.Reader
		var err error
		switch enc {
		case "gzip":
			r, err = gzip.NewReader(rec.Body)
		case "br":
			r = brotli.NewReader(rec.Body)
		case "zstd":
			var d *zstd.Decoder
			d, err = zstd.NewReader(rec.Body)
			r = d
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || string(got) != compressBody {
			t.Errorf("%s: aller-retour invalide (err=%v, len=%d)", enc, err, len(got))
		}
	}
}

func TestCompressSkips(t *testing.T) {
	cfg := &router.CompressionConfig{Enabled: true, Algorithms: []string{"gzip"}}

	if rec := serveCompressed(t, cfg, "gzip", "image/png", nil); rec.Header().Get("Content-Encoding") != "" {
		t.Error("image/png ne doit pas être compressé")
	}
	if rec := serveCompressed(t, cfg, "gzip", "text/event-stream", nil); rec.Header().Get("Content-Encoding") != "" {
		t.Error("SSE ne doit pas être compressé")
	}
	small := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "0123456789")
	}
	if rec := serveCompressed(t, cfg, "gzip", "", small); rec.Header().Get("Content-Encoding") != "" {
		t.Error("réponse sous min_length ne doit pas être compressée")
	}
	already := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, compressBody)
	}
	if rec := serveCompressed(t, cfg, "gzip", "", already); rec.Header().Get("Content-Encoding") != "br" {
		t.Error("Content-Encoding du backend doit être conservé")
	}
	notModified := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotModified)
	}
	if rec := serveCompressed(t, cfg, "gzip", "", notModified); rec.Header().Get("Content-Encoding") != "" {
		t.Error("304 ne doit pas être compressé")
	}
	if rec := serveCompressed(t, &router.CompressionConfig{Enabled: false}, "gzip", "text/html", nil); rec.Header().Get("Content-Encoding") != "" {
		t.Error("désactivé : aucune compression")
	}
}

func TestCompressWeakensETagAndDropsLength(t *testing.T) {
	cfg := &router.CompressionConfig{Enabled: true, Algorithms: []string{"gzip"}}
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Content-Length", "5000")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 5000))
	}
	rec := serveCompressed(t, cfg, "gzip", "", h)
	if rec.Header().Get("ETag") != `W/"abc"` {
		t.Errorf("ETag = %q", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Content-Length") != "" {
		t.Error("Content-Length doit être retiré")
	}
}
