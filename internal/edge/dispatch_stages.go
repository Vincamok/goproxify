// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"sort"

	"github.com/vincamok/goproxify/internal/edge/geoip"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// dispatchStage est une étape de la chaîne d'une route. rank donne sa place dans la vie d'une requête : plus petit =
// plus tôt. Les détecteurs (WAF, bot, filtre IP, GeoIP) viennent du registre avec leur propre rang
// (middleware.Rank*) ; les autres étapes ont le leur ici, sur la même échelle.
type dispatchStage struct {
	name string
	rank int
	wrap func(http.Handler) http.Handler
}

// Rangs des étapes qui ne sont pas des détecteurs. Les rangs vides (700, 800, 1300, 1500) sont ceux du WAF, du bot,
// du filtre IP et de GeoIP : voir middleware/detector_exec.go. Un test contrôle que les deux échelles se tiennent.
const (
	rankMaintenance     = 100
	rankSignedURL       = 200
	rankBandwidth       = 300
	rankCompress        = 400
	rankTransform       = 500
	rankRequestID       = 600
	rankRequestVars     = 900
	rankBackpressure    = 1000
	rankLimitConn       = 1100
	rankRateLimit       = 1200
	rankPlugins         = 1400
	rankSecurityHeaders = 1600
	rankCORS            = 1700
	rankMTLS            = 1800
	rankJWT             = 1900
	rankSSO             = 2000
	rankOpenAPI         = 2100
	rankRequestSchema   = 2200
	rankGraphQL         = 2300
)

func (s *Server) detectorEnv() middleware.DetectorEnv {
	return middleware.DetectorEnv{
		GeoIPDBPath: func(route *router.Route) string {
			dbPath := route.GeoIP.DBPath
			if dbPath == "" && s.cfg != nil {
				dbPath = s.cfg.GeoIP.DBPath
			}
			if dbPath == "" {
				dbPath = geoip.DefaultDBPath
			}
			return dbPath
		},
		WAF: func(cfg *router.WAFConfig, next http.Handler) http.Handler { return s.wafEngine.Middleware(cfg, next) },
	}
}

// dispatchStages assemble les étapes de la chaîne d'une route, triées de la première (extérieure) à la dernière
// (la plus proche du backend). Le premier cache, le handler et le transcodage gRPC sont en dessous : voir
// handlerForRoute.
func (s *Server) dispatchStages(route *router.Route, key string) []dispatchStage {
	stages := []dispatchStage{
		{"maintenance", rankMaintenance, middleware.Maintenance(route.Maintenance)},
		{"signed_url", rankSignedURL, middleware.SignedURL(route.SignedURL)},
		{"bandwidth", rankBandwidth, middleware.Bandwidth(route.Bandwidth)},
		{"compress", rankCompress, middleware.Compress(route.Compression)},
		{"transform", rankTransform, middleware.Transform(route.Transform)},
		{"request_vars", rankRequestVars, middleware.ResolveRequestVars(route.RequestVars)},
		{"backpressure", rankBackpressure, middleware.BackpressureShared(key, route.Host, route.Backpressure)},
		{"limit_conn", rankLimitConn, middleware.LimitConn(route.ID, route.LimitConn)},
		{"rate_limit", rankRateLimit, middleware.RateLimit(route.RateLimit)},
		{"security_headers", rankSecurityHeaders, middleware.SecurityHeaders(route.Headers)},
		{"cors", rankCORS, middleware.CORS(route.CORS)},
		{"mtls", rankMTLS, middleware.MTLSValidation(route.MTLS)},
		{"jwt", rankJWT, middleware.JWTValidation(route.JWT)},
		{"sso", rankSSO, middleware.SSOAuth(route.SSO)},
		{"openapi", rankOpenAPI, middleware.OpenAPI(route.Host, route.OpenAPI)},
		{"request_schema", rankRequestSchema, middleware.RequestSchema(route.Host, route.RequestSchema)},
		{"graphql", rankGraphQL, middleware.GraphQLLimits(route.GraphQL)},
	}
	if route.RequestID != nil && !*route.RequestID {
		stages = append(stages, dispatchStage{"request_id", rankRequestID, stripRequestIDResponse})
	}
	if len(route.Plugins) > 0 {
		// Après le WAF, le bot, le débit et les filtres réseau (qui s'exécutent avant) ; avant l'authentification.
		stages = append(stages, dispatchStage{"plugins", rankPlugins, s.pluginMiddleware(route)})
	}
	for _, d := range middleware.DetectorStages(route, s.detectorEnv()) {
		stages = append(stages, dispatchStage{d.Type, d.Rank, d.Wrap})
	}
	sort.SliceStable(stages, func(i, j int) bool { return stages[i].rank < stages[j].rank })
	return stages
}

// wrapStages enveloppe h des étapes, la dernière de la liste en premier : la première de la liste voit la requête
// avant toutes les autres.
func wrapStages(h http.Handler, stages []dispatchStage) http.Handler {
	for i := len(stages) - 1; i >= 0; i-- {
		if stages[i].wrap != nil {
			h = stages[i].wrap(h)
		}
	}
	return h
}
