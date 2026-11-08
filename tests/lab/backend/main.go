package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func intQ(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil && v >= 0 {
		return v
	}
	return def
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Renvoie ce que le backend a réellement reçu du proxy (tests d'en-têtes / IP réelle).
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":   r.Method,
			"host":     r.Host,
			"uri":      r.RequestURI,
			"remote":   r.RemoteAddr,
			"headers":  r.Header,
			"body_len": len(body),
		})
	})

	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(intQ(r, "ms", 500)) * time.Millisecond)
		fmt.Fprint(w, "slow ok")
	})

	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		if rand.Intn(100) < intQ(r, "p", 20) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n := intQ(r, "n", 1024)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := []byte(strings.Repeat("x", 4096))
		for n > 0 {
			c := min(n, len(chunk))
			if _, err := w.Write(chunk[:c]); err != nil {
				return
			}
			n -= c
		}
	})

	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		if err != nil || code < 100 || code > 599 {
			code = http.StatusBadRequest
		}
		w.WriteHeader(code)
	})

	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "%d", n)
	})

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < intQ(r, "n", 10); i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(intQ(r, "ms", 200)) * time.Millisecond):
			}
		}
	})

	addr := ":9000"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
