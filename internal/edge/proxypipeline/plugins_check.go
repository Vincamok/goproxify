// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"fmt"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// validatePlugins vérifie les plugins d'une route : installé sur la passerelle, présent une seule fois,
// configuration conforme à son manifeste.
func validatePlugins(route *router.Route, opts DryRunOptions) []string {
	return ValidatePluginRefs(route, opts.KnownPlugins, true)
}

// ValidatePluginRefs vérifie les plugins d'une route contre les manifestes installés (known). Avec
// requireInstalled, un plugin absent est une erreur (dry-run d'un proxy) ; sans, il est toléré — route découverte
// par labels, dont le plugin peut arriver de l'Admin après le conteneur : la route refuse alors le trafic (503)
// jusqu'à son arrivée, mais n'est pas rejetée.
func ValidatePluginRefs(route *router.Route, known map[string]plugins.Manifest, requireInstalled bool) []string {
	var errs []string
	seen := map[string]bool{}
	for i, ref := range route.Plugins {
		if strings.TrimSpace(ref.Name) == "" {
			errs = append(errs, fmt.Sprintf("plugins[%d].name vide", i))
			continue
		}
		if seen[ref.Name] {
			errs = append(errs, fmt.Sprintf("plugin %q en double", ref.Name))
		}
		seen[ref.Name] = true
		if known == nil {
			continue
		}
		man, ok := known[ref.Name]
		if !ok {
			if requireInstalled {
				errs = append(errs, fmt.Sprintf("plugin inconnu %q", ref.Name))
			}
			continue
		}
		if err := man.ConfigManifest().Validate(ref.Config); err != nil {
			errs = append(errs, fmt.Sprintf("plugin %s : %v", ref.Name, err))
		}
		// Un plugin sans hook applicable au type de la route ne ferait jamais rien : mieux vaut le dire.
		l4 := routeIsL4(route.Type)
		applicable := false
		for _, h := range man.Hooks {
			if (h == plugins.HookConnect) == l4 {
				applicable = true
			}
		}
		if !applicable {
			kind := "HTTP (request, response, request_body, response_body)"
			if l4 {
				kind = "TCP/UDP (connect)"
			}
			errs = append(errs, fmt.Sprintf("plugin %s : aucun hook applicable à une route %s", ref.Name, kind))
		}
	}
	return errs
}
