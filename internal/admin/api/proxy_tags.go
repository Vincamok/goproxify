// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"unicode"

	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const maxProxyNameLen = 128

// ValidateProxyIdentity vérifie le nom et les étiquettes d'un proxy, ce que les périmètres de droits lisent (ADR 0022).
func ValidateProxyIdentity(route *router.Route) error {
	if len(route.Name) > maxProxyNameLen {
		return fmt.Errorf("nom : %d caractères au plus", maxProxyNameLen)
	}
	if strings.IndexFunc(route.Name, unicode.IsControl) >= 0 {
		return fmt.Errorf("nom : caractères de contrôle interdits")
	}
	return rbac.ValidateLabels(route.Labels)
}

// LabelChange décrit en une ligne ce qui change entre deux jeux d'étiquettes, ou "" s'ils sont identiques : c'est ce
// que le journal d'audit retient quand une équipe pose ou retire une étiquette qui la fait entrer dans un périmètre.
func LabelChange(before, after map[string]string) string {
	if maps.Equal(before, after) {
		return ""
	}
	var parts []string
	for k, v := range after {
		if old, ok := before[k]; !ok {
			parts = append(parts, "+"+k+"="+v)
		} else if old != v {
			parts = append(parts, k+": "+old+" → "+v)
		}
	}
	for k, v := range before {
		if _, ok := after[k]; !ok {
			parts = append(parts, "-"+k+"="+v)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
