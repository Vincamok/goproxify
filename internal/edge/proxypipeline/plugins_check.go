// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"fmt"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// validatePlugins vérifie les plugins d'une route : installé sur la passerelle, présent une seule fois,
// configuration conforme à son manifeste.
func validatePlugins(route *router.Route, opts DryRunOptions) []string {
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
		if opts.KnownPlugins == nil {
			continue
		}
		man, ok := opts.KnownPlugins[ref.Name]
		if !ok {
			errs = append(errs, fmt.Sprintf("plugin inconnu %q", ref.Name))
			continue
		}
		if err := man.ConfigManifest().Validate(ref.Config); err != nil {
			errs = append(errs, fmt.Sprintf("plugin %s : %v", ref.Name, err))
		}
	}
	return errs
}
