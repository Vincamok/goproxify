// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/modules"
)

func (h *Handler) toolListDNSProviders() (any, error) {
	if h.DNSProviders == nil {
		return nil, fmt.Errorf("fournisseurs DNS non disponibles")
	}
	entries, err := h.DNSProviders.List()
	if err != nil {
		return nil, err
	}
	out := make([]acme.ProviderEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Masked())
	}
	return out, nil
}

// dnsProviderTypes filtre les manifestes : 33 types, un client IA cherche le sien plutôt que tout relire.
func dnsProviderTypes(q string) []modules.Manifest {
	all := acme.DNSProviderManifests()
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return all
	}
	out := []modules.Manifest{}
	for _, m := range all {
		if strings.Contains(strings.ToLower(m.Type), q) || strings.Contains(strings.ToLower(m.Label), q) {
			out = append(out, m)
		}
	}
	return out
}
