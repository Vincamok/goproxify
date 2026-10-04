package middleware

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const defaultCompressMinLength = 1024

var defaultCompressAlgorithms = []string{"zstd", "br", "gzip"}

var defaultCompressTypes = []string{
	"text/*",
	"application/json",
	"application/javascript",
	"application/x-javascript",
	"application/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"application/manifest+json",
	"application/wasm",
	"image/svg+xml",
	"image/x-icon",
	"font/ttf",
	"font/otf",
	"application/vnd.ms-fontobject",
}

// Compress compresse les réponses selon Accept-Encoding. Retourne un passe-plat si cfg est nil ou désactivée.
func Compress(cfg *router.CompressionConfig) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	c := &compressor{
		algos:     normalizeAlgorithms(cfg.Algorithms),
		minLength: cfg.MinLength,
		level:     cfg.Level,
		types:     cfg.Types,
	}
	if c.minLength <= 0 {
		c.minLength = defaultCompressMinLength
	}
	if len(c.types) == 0 {
		c.types = defaultCompressTypes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			enc := c.negotiate(r)
			if enc == "" || r.Method == http.MethodHead || isUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}
			cw := &compressWriter{ResponseWriter: w, c: c, enc: enc}
			defer cw.close()
			next.ServeHTTP(cw, r)
		})
	}
}

type compressor struct {
	algos     []string
	minLength int
	level     int
	types     []string

	gzPool sync.Pool
	zsPool sync.Pool
	brPool sync.Pool
}

func normalizeAlgorithms(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range in {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "brotli" {
			a = "br"
		}
		if (a == "zstd" || a == "br" || a == "gzip") && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return defaultCompressAlgorithms
	}
	return out
}

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != ""
}

// negotiate choisit l'encodage : meilleure préférence serveur parmi ceux acceptés par le client (q > 0).
func (c *compressor) negotiate(r *http.Request) string {
	ae := r.Header.Get("Accept-Encoding")
	if ae == "" {
		return ""
	}
	accepted := map[string]bool{}
	star := false
	for _, part := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		ok := true
		if k, v, found := strings.Cut(strings.ReplaceAll(params, " ", ""), "="); found && strings.EqualFold(k, "q") {
			if q, err := strconv.ParseFloat(v, 64); err == nil && q <= 0 {
				ok = false
			}
		}
		if name == "*" {
			star = ok
		} else {
			accepted[name] = ok
		}
	}
	for _, a := range c.algos {
		if ok, set := accepted[a]; set {
			if ok {
				return a
			}
		} else if star {
			return a
		}
	}
	return ""
}

func (c *compressor) compressible(ct string) bool {
	ct, _, _ = strings.Cut(ct, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" || ct == "text/event-stream" {
		return false
	}
	for _, t := range c.types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == ct || (strings.HasSuffix(t, "/*") && strings.HasPrefix(ct, t[:len(t)-1])) {
			return true
		}
	}
	return false
}

func (c *compressor) newEncoder(enc string, w io.Writer) io.WriteCloser {
	switch enc {
	case "gzip":
		if z, ok := c.gzPool.Get().(*gzip.Writer); ok {
			z.Reset(w)
			return z
		}
		z, _ := gzip.NewWriterLevel(w, c.gzipLevel())
		return z
	case "zstd":
		if z, ok := c.zsPool.Get().(*zstd.Encoder); ok {
			z.Reset(w)
			return z
		}
		z, _ := zstd.NewWriter(w, zstd.WithEncoderLevel(c.zstdLevel()), zstd.WithEncoderConcurrency(1))
		return z
	default:
		if z, ok := c.brPool.Get().(*brotli.Writer); ok {
			z.Reset(w)
			return z
		}
		return brotli.NewWriterLevel(w, c.brotliLevel())
	}
}

func (c *compressor) release(e io.WriteCloser) {
	switch z := e.(type) {
	case *gzip.Writer:
		c.gzPool.Put(z)
	case *zstd.Encoder:
		c.zsPool.Put(z)
	case *brotli.Writer:
		c.brPool.Put(z)
	}
}

func (c *compressor) gzipLevel() int {
	if c.level < 1 {
		return 6
	}
	return c.clampLevel()
}

func (c *compressor) brotliLevel() int {
	if c.level < 1 {
		return 4
	}
	return c.clampLevel() + 2 // 1..9 → 3..11 : brotli à bas niveau reste rapide en dynamique
}

func (c *compressor) zstdLevel() zstd.EncoderLevel {
	switch {
	case c.level < 1:
		return zstd.SpeedDefault
	case c.level <= 2:
		return zstd.SpeedFastest
	case c.level <= 5:
		return zstd.SpeedDefault
	case c.level <= 7:
		return zstd.SpeedBetterCompression
	default:
		return zstd.SpeedBestCompression
	}
}

type compressWriter struct {
	http.ResponseWriter
	c       *compressor
	enc     string
	decided bool
	status  int
	encoder    io.WriteCloser
}

func (w *compressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *compressWriter) WriteHeader(code int) {
	if w.decided {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.decided = true
	w.status = code
	h := w.Header()
	if w.shouldCompress(code, h) {
		h.Set("Content-Encoding", w.enc)
		h.Del("Content-Length")
		if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
			h.Set("ETag", "W/"+etag)
		}
		w.encoder = w.c.newEncoder(w.enc, w.ResponseWriter)
	}
	if w.shouldVary(h) {
		h.Add("Vary", "Accept-Encoding")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *compressWriter) shouldVary(h http.Header) bool {
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			f = strings.TrimSpace(f)
			if f == "*" || strings.EqualFold(f, "Accept-Encoding") {
				return false
			}
		}
	}
	return true
}

func (w *compressWriter) shouldCompress(code int, h http.Header) bool {
	switch {
	case code < 200, code == http.StatusNoContent, code == http.StatusNotModified, code == http.StatusPartialContent:
		return false
	case h.Get("Content-Encoding") != "", h.Get("Content-Range") != "":
		return false
	case strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform"):
		return false
	}
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n < w.c.minLength {
			return false
		}
	}
	return w.c.compressible(h.Get("Content-Type"))
}

func (w *compressWriter) Write(b []byte) (int, error) {
	if !w.decided {
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", http.DetectContentType(b))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.encoder == nil {
		return w.ResponseWriter.Write(b)
	}
	return w.encoder.Write(b)
}

func (w *compressWriter) Flush() {
	if w.encoder != nil {
		if f, ok := w.encoder.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *compressWriter) close() {
	if w.encoder != nil {
		_ = w.encoder.Close()
		w.c.release(w.encoder)
		w.encoder = nil
	}
}

func (c *compressor) clampLevel() int {
	if c.level > 9 {
		return 9
	}
	return c.level
}
