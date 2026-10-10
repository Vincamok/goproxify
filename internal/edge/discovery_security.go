// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"encoding/json"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/geoip"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/labels"
)

// applyDiscoverySecurity pose sur la route les protections issues des labels Docker.
// Les champs absents du payload ne sont pas effacés (merge multi-backends).
// Les champs présents (y compris listes vides pour snippet_ids) remplacent la valeur.
func applyDiscoverySecurity(rt *router.Route, p *agentContainerPayload, defaultGeoDB string) {
	if rt == nil || p == nil {
		return
	}
	if cfg := decodeRateLimit(p.RateLimit); cfg != nil {
		rt.RateLimit = cfg
	}
	if cfg := decodeIPFilter(p.IPFilter); cfg != nil {
		rt.IPFilter = cfg
	}
	if cfg := decodeCORS(p.CORS); cfg != nil {
		rt.CORS = cfg
	}
	if cfg := decodeGeoIP(p.GeoIP, defaultGeoDB); cfg != nil {
		rt.GeoIP = cfg
	}
	if p.SnippetIDs != nil {
		rt.SnippetIDs = append([]string(nil), p.SnippetIDs...)
	}
	if p.AuthProviderID != "" {
		rt.AuthProviderID = p.AuthProviderID
	}
	if p.Plugins != nil {
		rt.Plugins = append([]router.PluginRef(nil), p.Plugins...)
	}
	if cfg := decodeWAF(p.WAF); cfg != nil {
		rt.WAF = cfg
	}
	if cfg := decodeBot(p.Bot); cfg != nil {
		rt.Bot = cfg
	}
	if len(p.SentinelWhitelist) > 0 {
		rt.SentinelWhitelist = append([]string(nil), p.SentinelWhitelist...)
	}
}

func decodeRateLimit(raw json.RawMessage) *router.RateLimitConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.RateLimitConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && cfg.RequestsPerSecond > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseRateLimit(s)
	}
	return nil
}

func decodeIPFilter(raw json.RawMessage) *router.IPFilterConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.IPFilterConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && len(cfg.CIDRs) > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseIPFilter(s)
	}
	return nil
}

func decodeCORS(raw json.RawMessage) *router.CORSConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.CORSConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && len(cfg.AllowedOrigins) > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseCORS(s)
	}
	return nil
}

func decodeGeoIP(raw json.RawMessage, defaultDB string) *router.GeoIPConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.GeoIPConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && (len(cfg.Countries) > 0 || cfg.Mode != "") {
		if cfg.DBPath == "" {
			cfg.DBPath = defaultDB
		}
		if cfg.DBPath == "" {
			cfg.DBPath = geoip.DefaultDBPath
		}
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		g := labels.ParseGeoIP(s)
		if g == nil {
			return nil
		}
		if g.DBPath == "" {
			g.DBPath = defaultDB
		}
		if g.DBPath == "" {
			g.DBPath = geoip.DefaultDBPath
		}
		return g
	}
	return nil
}

func decodeWAF(raw json.RawMessage) *router.WAFConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.WAFConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && cfg.Enabled {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseWAF(s)
	}
	return nil
}

func decodeBot(raw json.RawMessage) *router.BotConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.BotConfig
	if err := json.Unmarshal(raw, &cfg); err == nil {
		router.NormalizeBotConfig(&cfg)
		if cfg.Enabled {
			return &cfg
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseBot(s)
	}
	return nil
}

func rawPresent(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != `""`
}

// discoverySecurityErrors valide la sécurité portée par les labels d'un conteneur avant d'enregistrer la
// route : les mêmes manifestes et contrôles que le dry-run d'un proxy, et un filtre IP ou GeoIP présent
// mais illisible est une erreur (le décodeur le supprimait en silence, laissant la route sans filtre).
// Seules les erreurs intrinsèques comptent : un snippet ou un fournisseur encore absent est géré à
// l'exécution (503), pas ici, puisqu'il peut arriver après le conteneur.
func discoverySecurityErrors(p *agentContainerPayload, geoDB string, known map[string]plugins.Manifest) []string {
	probe := &router.Route{Type: router.RouteHTTP}
	applyDiscoverySecurity(probe, p, geoDB)
	errs := append([]string(nil), p.LabelErrors...)
	errs = append(errs, middleware.ValidateRouteDetectors(probe)...)
	errs = append(errs, proxypipeline.ValidatePluginRefs(probe, known, false)...)
	if rawPresent(p.IPFilter) && probe.IPFilter == nil {
		errs = append(errs, "ip_filter : valeur illisible ou sans adresse (attendu allow:<cidr>,… ou deny:<cidr>,…)")
	}
	if rawPresent(p.GeoIP) && probe.GeoIP == nil {
		errs = append(errs, "geo_ip : valeur illisible (attendu allow:FR,DE ou deny:CN,RU)")
	}
	return errs
}
