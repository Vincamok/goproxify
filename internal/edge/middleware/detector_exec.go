// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"sort"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Exécution des détecteurs par route (ADR 0007). Le registre ne fait pas que décrire : chaque détecteur porte aussi
// la construction de son middleware (Build) et son rang dans la chaîne. L'ordre ne se déduit pas de l'ordre
// d'enregistrement — le WAF juge avant le filtre IP, qui juge avant les plugins et GeoIP, et ils s'intercalent avec le
// débit, la contre-pression et l'authentification, qui ne sont pas des détecteurs —, d'où un rang explicite sur la
// même échelle que les autres étapes de la chaîne (dispatch_stages.go).

// Rangs d'exécution : plus petit = plus tôt dans la vie d'une requête.
const (
	RankWAF      = 700
	RankBot      = 800
	RankIPFilter = 1300
	RankGeoIP    = 1500
)

// DetectorEnv porte ce que seul le serveur sait construire.
type DetectorEnv struct {
	// GeoIPDBPath résout la base GeoIP d'une route (réglage de la route, de la passerelle, ou chemin par défaut).
	GeoIPDBPath func(route *router.Route) string
	// WAF enveloppe next avec le moteur WAF de la passerelle.
	WAF func(cfg *router.WAFConfig, next http.Handler) http.Handler
}

// DetectorBuild construit le middleware d'un détecteur pour une route ; nil si le détecteur n'est pas actif sur elle
// (la chaîne ne l'enveloppe alors pas du tout).
type DetectorBuild func(route *router.Route, env DetectorEnv) func(http.Handler) http.Handler

type detectorExec struct {
	rank  int
	build DetectorBuild
}

var detectorExecs = map[string]detectorExec{}

// SetDetectorExec attache l'exécution au détecteur de ce type. À appeler depuis init() ; le détecteur lui-même
// est enregistré par RegisterDetector dans un autre fichier du paquet, dont l'init() peut passer après celui-ci (l'ordre
// suit le nom des fichiers) : la correspondance est donc contrôlée par un test, pas ici.
func SetDetectorExec(typ string, rank int, build DetectorBuild) {
	if _, dup := detectorExecs[typ]; dup {
		panic("exécution du détecteur déjà déclarée : " + typ)
	}
	detectorExecs[typ] = detectorExec{rank: rank, build: build}
}

// DetectorStage est un détecteur actif sur une route, prêt à être placé dans la chaîne.
type DetectorStage struct {
	Type string
	Rank int
	Wrap func(http.Handler) http.Handler
}

// DetectorStages retourne les détecteurs actifs de la route, triés par rang. Chacun est enveloppé d'un observateur
// qui compte ses décisions (gpx_detector_decisions_total).
func DetectorStages(route *router.Route, env DetectorEnv) []DetectorStage {
	var out []DetectorStage
	for typ, ex := range detectorExecs {
		wrap := ex.build(route, env)
		if wrap == nil {
			continue
		}
		out = append(out, DetectorStage{Type: typ, Rank: ex.rank, Wrap: observeDecisions(typ, wrap)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out
}

type probeKey struct{ detector string }

type decisionProbe struct{ passed bool }

// observeDecisions compte, par détecteur, les requêtes qu'il laisse passer (il appelle la suite) et celles qu'il
// arrête (il répond lui-même). Un détecteur en mode détection laisse passer : il compte comme tel.
func observeDecisions(name string, wrap func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		pass := metrics.Detector.Decisions.WithLabelValues(name, "pass")
		block := metrics.Detector.Decisions.WithLabelValues(name, "block")
		key := probeKey{name}
		inner := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := r.Context().Value(key).(*decisionProbe); ok {
				p.passed = true
			}
			pass.Inc()
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &decisionProbe{}
			inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), key, p)))
			if !p.passed {
				block.Inc()
			}
		})
	}
}

func init() {
	SetDetectorExec("waf", RankWAF, func(route *router.Route, env DetectorEnv) func(http.Handler) http.Handler {
		if route.WAF == nil || !route.WAF.Enabled || env.WAF == nil {
			return nil
		}
		cfg := route.WAF
		return func(next http.Handler) http.Handler { return env.WAF(cfg, next) }
	})
	SetDetectorExec("bot", RankBot, func(route *router.Route, _ DetectorEnv) func(http.Handler) http.Handler {
		if route.Bot == nil || !route.Bot.Enabled {
			return nil
		}
		return BotProtection(route.Bot)
	})
	SetDetectorExec("ip_filter", RankIPFilter, func(route *router.Route, _ DetectorEnv) func(http.Handler) http.Handler {
		if route.IPFilter == nil || len(route.IPFilter.CIDRs) == 0 {
			return nil
		}
		return IPFilter(route.IPFilter)
	})
	SetDetectorExec("geo_ip", RankGeoIP, func(route *router.Route, env DetectorEnv) func(http.Handler) http.Handler {
		if route.GeoIP == nil || env.GeoIPDBPath == nil {
			return nil
		}
		return GeoIP(env.GeoIPDBPath(route), route.GeoIP.Mode, route.GeoIP.Countries)
	})
}
