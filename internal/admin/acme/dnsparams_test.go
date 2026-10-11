// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import "testing"

func TestValidateDNSParams_OVHEndpoint(t *testing.T) {
	for _, ep := range []any{nil, "", "ovh-eu", "OVH-CA", "https://eu.api.ovh.com/1.0", "https://api.kimsufi.example/1.0"} {
		if err := ValidateDNSParams("ovh", map[string]any{"endpoint": ep}); err != nil {
			t.Errorf("%v refusé : %v", ep, err)
		}
	}
	for _, ep := range []string{"http://eu.api.ovh.com/1.0", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.0.0.5/1.0", "https://localhost/1.0", "ftp://x", "pas-une-url", "e"} {
		if err := ValidateDNSParams("ovh", map[string]any{"endpoint": ep}); err == nil {
			t.Errorf("%q accepté", ep)
		}
	}
	if err := ValidateDNSParams("cloudflare", map[string]any{"endpoint": "http://x"}); err != nil {
		t.Errorf("un autre fournisseur n'est pas concerné : %v", err)
	}
}
