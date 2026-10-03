// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// SecurityHeaders applique les headers de sécurité HTTP et masque le fingerprint serveur.
func SecurityHeaders(cfg *router.HeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if cfg.HideServer {
				w = &hideServerWriter{ResponseWriter: w}
			}
			if cfg.HSTS {
				age := cfg.HSTSMaxAge
				if age == 0 {
					age = 31536000
				}
				h.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", age))
			}
			if cfg.XFrameOptions != "" {
				h.Set("X-Frame-Options", cfg.XFrameOptions)
			}
			for k, v := range cfg.Custom {
				h.Set(k, v)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hideServerWriter retire Server et X-Powered-By au moment de l'envoi des en-têtes :
// le reverse proxy y copie ceux du backend après le passage du middleware.
type hideServerWriter struct {
	http.ResponseWriter
	sent bool
}

func (w *hideServerWriter) strip() {
	if w.sent {
		return
	}
	w.sent = true
	h := w.ResponseWriter.Header()
	h.Del("Server")
	h.Del("X-Powered-By")
}

func (w *hideServerWriter) WriteHeader(code int) {
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.strip()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hideServerWriter) Write(b []byte) (int, error) {
	w.strip()
	return w.ResponseWriter.Write(b)
}

func (w *hideServerWriter) Flush() {
	w.strip()
	http.NewResponseController(w.ResponseWriter).Flush() //nolint:errcheck
}

func (w *hideServerWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// CORS applique les headers CORS selon la configuration de la route.
func CORS(cfg *router.CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, cfg.AllowedOrigins) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				if len(cfg.AllowedMethods) > 0 {
					h.Set("Access-Control-Allow-Methods", joinStrings(cfg.AllowedMethods))
				}
				if len(cfg.AllowedHeaders) > 0 {
					h.Set("Access-Control-Allow-Headers", joinStrings(cfg.AllowedHeaders))
				}
				if cfg.MaxAge > 0 {
					h.Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
				}
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OriginAllowed indique si l'en-tête Origin figure dans la liste (le joker * n'est jamais accepté).
func OriginAllowed(origin string, allowed []string) bool { return originAllowed(origin, allowed) }

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" {
			continue // * interdit (M6)
		}
		if a == origin {
			return true
		}
	}
	return false
}

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
