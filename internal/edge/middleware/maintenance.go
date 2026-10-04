package middleware

import (
	"html"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Maintenance répond 503 + Retry-After tant que la route est en maintenance.
// Les IP de BypassCIDRs et les requêtes portant BypassHeader passent normalement.
func Maintenance(cfg *router.MaintenanceConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		var bypass []netip.Prefix
		for _, c := range cfg.BypassCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil {
				bypass = append(bypass, p)
			} else if a, err := netip.ParseAddr(c); err == nil {
				bypass = append(bypass, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		hdrName, hdrValue, _ := strings.Cut(cfg.BypassHeader, ":")
		hdrName, hdrValue = strings.TrimSpace(hdrName), strings.TrimSpace(hdrValue)
		retry := cfg.RetryAfterSec
		if retry <= 0 {
			retry = 300
		}
		msg := cfg.Message
		if msg == "" {
			msg = "Ce service est en maintenance. Merci de réessayer dans quelques instants."
		}
		page := cfg.HTML
		if page == "" {
			page = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance</title>` +
				`<body style="font:16px system-ui;display:grid;place-items:center;min-height:100vh;margin:0"><main style="max-width:32rem;padding:2rem;text-align:center"><h1>Maintenance</h1><p>` +
				html.EscapeString(msg) + `</p></main></body>`
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hdrName != "" && r.Header.Get(hdrName) == hdrValue {
				next.ServeHTTP(w, r)
				return
			}
			if len(bypass) > 0 {
				if ip, err := netip.ParseAddr(clientIP(r)); err == nil {
					ip = ip.Unmap()
					for _, p := range bypass {
						if p.Contains(ip) {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(page))
			}
		})
	}
}
