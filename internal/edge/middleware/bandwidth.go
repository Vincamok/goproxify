package middleware

import (
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Bandwidth plafonne le débit de chaque réponse (par connexion), comme nginx limit_rate.
func Bandwidth(cfg *router.BandwidthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || cfg.BytesPerSec <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&throttledWriter{ResponseWriter: w, rate: cfg.BytesPerSec, start: time.Now(), done: r.Context().Done()}, r)
		})
	}
}

type throttledWriter struct {
	http.ResponseWriter
	rate  int64
	sent  int64
	start time.Time
	done  <-chan struct{}
}

func (t *throttledWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

func (t *throttledWriter) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (t *throttledWriter) Write(p []byte) (int, error) {
	total := 0
	chunk := int(max(t.rate/10, 1024))
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		w, err := t.ResponseWriter.Write(p[:n])
		total += w
		t.sent += int64(w)
		if err != nil {
			return total, err
		}
		p = p[n:]
		t.Flush()
		due := t.start.Add(time.Duration(float64(t.sent) / float64(t.rate) * float64(time.Second)))
		if d := time.Until(due); d > 0 && len(p) > 0 {
			select {
			case <-time.After(d):
			case <-t.done:
				return total, http.ErrAbortHandler
			}
		}
	}
	return total, nil
}
