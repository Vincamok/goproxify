// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/admin/logs"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/httpx"
)

// --- Middleware & helpers -------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

// Unwrap laisse http.ResponseController atteindre le vrai écrivain (délais par requête).
func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// pollingPrefixes liste les lectures que l'interface rappelle toutes les 4 à 30 s : une ligne par
// appel noyait la table logs (une page ouverte = plus de 17 000 lignes par jour et par onglet).
var pollingPrefixes = []string{
	"/api/v1/nodes/live",
	"/api/v1/metrics/",
	"/api/v1/prism/",
	"/api/v1/backends/health",
	"/api/v1/certs/acme-monitor",
	"/api/v1/portal/sessions",
}

var staticExts = []string{".js", ".css", ".map", ".svg", ".png", ".jpg", ".ico", ".woff", ".woff2"}

// isPollingRead écarte du journal les lectures réussies de rafraîchissement et les fichiers
// statiques de l'interface ; les erreurs (>= 400) et toute écriture restent journalisées.
func isPollingRead(method, path string, status int) bool {
	if (method != http.MethodGet && method != http.MethodHead) || status >= 400 {
		return false
	}
	for _, p := range pollingPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	if strings.HasPrefix(path, "/api/") {
		return false
	}
	for _, e := range staticExts {
		if strings.HasSuffix(path, e) {
			return true
		}
	}
	return false
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		elapsed := time.Since(start).Seconds()
		statusStr := fmt.Sprintf("%d", sw.status)
		adminmetrics.AdminHTTP.RequestsTotal.WithLabelValues(r.Method, statusStr).Inc()
		adminmetrics.AdminHTTP.Duration.WithLabelValues(r.Method).Observe(elapsed)

		if strings.HasPrefix(r.URL.Path, "/api/v1/health") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/logs/live") ||
			strings.HasPrefix(r.URL.Path, "/internal/v1/") ||
			isPollingRead(r.Method, r.URL.Path, sw.status) {
			return
		}
		latency := time.Since(start).Milliseconds()
		level := "info"
		if sw.status >= 500 {
			level = "error"
		} else if sw.status >= 400 {
			level = "warn"
		}
		ip := edgelog.RealIP(r)
		s.logStore.Write(logs.Entry{
			Level:     level,
			Component: "admin",
			Domain:    r.Host,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    sw.status,
			IP:        ip,
			LatencyMs: latency,
			Bytes:     sw.bytes,
			Referrer:  r.Header.Get("Referer"),
		})
	})
}

// runtimeSettings construit les settings runtime poussés aux passerelles.
func (s *Server) runtimeSettings() edgews.Settings {
	settings := edgews.Settings{
		TracingEndpoint: s.cfg.App.TracingEndpoint,
		LogLevel:        s.cfg.EdgeDefaults.LogLevel,
		LogFormat:       s.cfg.EdgeDefaults.LogFormat,
		AdminPublicURL:  explicitAdminPublicURL(),
	}
	if v := admindb.GetSetting(s.db, "logs.ip_anonymize", ""); v != "" {
		anon := v == "true"
		settings.IPAnonymize = &anon
	}
	if v := admindb.GetSetting(s.db, "logs.ip_pseudonymize", ""); v != "" {
		pseudo := v == "true"
		settings.IPPseudonymize = &pseudo
	}
	return settings
}

// cleanOrigin ne garde que l'origine http(s) bien formée (voir httpx.CleanOrigin).
var cleanOrigin = httpx.CleanOrigin

// explicitAdminPublicURL est l'origine de l'Admin que l'opérateur a déclarée (GPX_ADMIN_PUBLIC_URL). C'est la seule poussée
// aux passerelles pour le lien des pages d'erreur publiques : cette adresse apparaît dans des pages servies à n'importe
// quel visiteur, elle ne se déduit donc jamais d'une requête (Host et X-Forwarded-Host sont choisis par l'appelant).
func explicitAdminPublicURL() string {
	return cleanOrigin(os.Getenv("GPX_ADMIN_PUBLIC_URL"))
}

// resolveAdminPublicURL retourne l'origine publique de l'Admin pour les liens d'enrôlement (env > origine WebAuthn).
func (s *Server) resolveAdminPublicURL() string {
	if u := explicitAdminPublicURL(); u != "" {
		return u
	}
	return cleanOrigin(admindb.GetSetting(s.db, "mfa.webauthn.origin", ""))
}

// publicOriginFromRequest déduit http(s)://host depuis la requête, pour un lien montré à l'appelant lui-même (enrôlement).
// Un schéma autre que http/https est ignoré et un hôte qui n'en est pas un (identifiants, chemin, espace) rend "".
func publicOriginFromRequest(r *http.Request) string {
	host, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ",")
	host = strings.TrimSpace(host)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" || strings.ContainsAny(host, "/?#@\\ \t") {
		return ""
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	return cleanOrigin(proto + "://" + host)
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type notFoundError struct{ email string }

func (e *notFoundError) Error() string { return "utilisateur introuvable : " + e.email }
