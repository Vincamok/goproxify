// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"log/slog"
	"strings"

	"github.com/vincamok/goproxify/internal/labels"
)

// AttachSecurityPayload ajoute les champs de sécurité et de comportement au payload Agent→Passerelle.
func AttachSecurityPayload(payload map[string]any, spec *ProxySpec) {
	if spec == nil {
		return
	}

	// Un label de sécurité présent mais illisible ne doit jamais donner une route sans cette protection :
	// les erreurs sont envoyées à la passerelle, qui refuse la route (label_errors).
	var labelErrors []string
	bad := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			labelErrors = append(labelErrors, "goproxify."+label+"="+value+" : valeur illisible")
		}
	}
	offWord := func(v string) bool { // « désactivé » explicite : pas une erreur
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "false", "0", "off", "no", "none", "disabled":
			return true
		}
		return false
	}

	// Sécurité réseau
	if rl := labels.ParseRateLimit(spec.RateLimit); rl != nil {
		payload["rate_limit"] = rl
	} else {
		bad("rate_limit", spec.RateLimit)
	}
	if ipf := labels.ParseIPFilter(spec.IPFilter); ipf != nil {
		payload["ip_filter"] = ipf
	} else {
		bad("ip_filter", spec.IPFilter)
	}
	if cors := labels.ParseCORS(spec.CORS); cors != nil {
		payload["cors"] = cors
	} else {
		bad("cors", spec.CORS)
	}
	if geo := labels.ParseGeoIP(spec.GeoIP); geo != nil {
		payload["geo_ip"] = geo
	} else {
		bad("geo_ip", spec.GeoIP)
	}
	if waf := labels.ParseWAF(spec.WAF); waf == nil && !offWord(spec.WAF) {
		bad("waf", spec.WAF)
	} else if waf != nil {
		labels.ParseWAFExtended(waf, spec.WAFAnomalyThreshold, spec.WAFMaxBodyMB,
			spec.WAFBehaviorWindow, spec.WAFBehaviorThreshold,
			spec.WAFExcludeIDs, spec.WAFTrustedProxies, spec.WAFBehavior)
		payload["waf"] = waf
	}
	if bot := labels.ParseBot(spec.Bot); bot != nil {
		labels.ParseBotMode(bot, spec.BotMode)
		payload["bot"] = bot
	} else if !offWord(spec.Bot) {
		bad("bot", spec.Bot)
	}
	if spec.LimitConn > 0 {
		payload["limit_conn"] = map[string]any{"max_per_ip": spec.LimitConn}
	}
	if bp := labels.ParseBackpressure(spec.Backpressure); bp != nil {
		payload["backpressure"] = bp
	} else {
		bad("backpressure", spec.Backpressure)
	}

	// Authentification
	if ids := labels.ParseCSVIDs(spec.SnippetIDs); len(ids) > 0 {
		payload["snippet_ids"] = ids
	}
	if id := strings.TrimSpace(spec.AuthProviderID); id != "" {
		payload["auth_provider_id"] = id
	}
	if v := strings.TrimSpace(spec.JWT); v != "" {
		if jc := labels.ParseJWT(v, spec.JWTIssuer, spec.JWTAudience); jc != nil {
			payload["jwt"] = jc
		} else {
			slog.Warn("label goproxify.jwt invalide : une URL JWKS (https://…) est attendue, la route est refusée", "host", spec.Host)
			bad("jwt", v)
		}
	}
	if v := strings.TrimSpace(spec.MTLS); v != "" {
		if mc := labels.ParseMTLS(v); mc != nil {
			payload["mtls"] = mc
		} else {
			slog.Warn("label goproxify.mtls invalide : le chemin d'un fichier CA est attendu, la route est refusée", "host", spec.Host)
			bad("mtls", v)
		}
	}

	// Plugins WASM : goproxify.plugins=a,b ; goproxify.plugin.a.<clé>=<valeur>.
	if names := labels.ParseCSVIDs(spec.Plugins); len(names) > 0 {
		refs := make([]map[string]any, 0, len(names))
		for _, n := range names {
			ref := map[string]any{"name": n}
			if cfg := spec.PluginConfig[n]; len(cfg) > 0 {
				ref["config"] = cfg
			}
			refs = append(refs, ref)
		}
		payload["plugins"] = refs
	}
	if len(labelErrors) > 0 {
		payload["label_errors"] = labelErrors
	}

	// Comportement HTTP
	if spec.PreserveHost {
		t := true
		payload["preserve_host"] = &t
	}
	if spec.Websocket {
		t := true
		payload["websocket"] = &t
	}
	if spec.RequestID {
		t := true
		payload["request_id"] = &t
	}
	if v := strings.TrimSpace(spec.HTTPVersion); v != "" {
		payload["http_version"] = v
	}

	// Réécriture d'URL
	if v := strings.TrimSpace(spec.StripPrefix); v != "" {
		payload["strip_prefix"] = v
	}
	if v := strings.TrimSpace(spec.PathRewrite); v != "" {
		payload["path_rewrite"] = v
	}

	// Timeouts & limites
	if v := strings.TrimSpace(spec.ConnectTimeout); v != "" {
		payload["connect_timeout"] = v
	}
	if v := strings.TrimSpace(spec.ResponseTimeout); v != "" {
		payload["response_timeout"] = v
	}
	if v := strings.TrimSpace(spec.SendTimeout); v != "" {
		payload["send_timeout"] = v
	}
	if v := strings.TrimSpace(spec.MaxBodySize); v != "" {
		payload["max_body_size"] = labels.ParseSize(v)
	}

	// Load balancing & résilience
	if v := strings.TrimSpace(spec.LB); v != "" {
		payload["lb"] = v
	}
	if v := strings.TrimSpace(spec.StickyCookie); v != "" {
		payload["sticky_cookie"] = v
	}
	if n := labels.ParseSlowStart(spec.SlowStart); n > 0 {
		payload["slow_start_sec"] = n
	}
	if v := strings.TrimSpace(spec.Retry); v != "" {
		payload["retry"] = labels.ParseRetry(v)
	}
	if v := strings.TrimSpace(spec.CircuitBreaker); v != "" {
		payload["circuit_breaker"] = labels.ParseCircuitBreaker(v)
	}

	// En-têtes
	if v := strings.TrimSpace(spec.AddHeaders); v != "" {
		payload["headers_add"] = labels.ParseHeaderList(v)
	}
	if v := strings.TrimSpace(spec.RemoveHeaders); v != "" {
		payload["headers_remove"] = labels.ParseHeaderRemoveList(v)
	}

	// Sentinel whitelist
	if cidrs := labels.ParseCSVIDs(spec.SentinelWhitelist); len(cidrs) > 0 {
		payload["sentinel_whitelist"] = cidrs
	}

	// Cache
	if v := strings.TrimSpace(spec.Cache); v != "" {
		payload["cache"] = labels.ParseCache(v)
	}

	// Logs
	if spec.LogForwarding || spec.LogFormat != "" || spec.LogLevel != "" {
		logging := map[string]any{"access_log": true}
		if spec.LogFormat != "" {
			logging["format"] = spec.LogFormat
		}
		if spec.LogLevel != "" {
			logging["level"] = spec.LogLevel
		}
		payload["logging"] = logging
	}
}
