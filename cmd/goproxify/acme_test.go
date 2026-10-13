// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDNSParamsMerge(t *testing.T) {
	file := filepath.Join(t.TempDir(), "params.json")
	if err := os.WriteFile(file, []byte(`{"service_account_json":"{\"a\":1,\"b\":2}","ttl":60}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := dnsParams(
		map[string]string{"api_token": "••••••••", "zone": "old.example.com"},
		map[string]string{"-file": file, "-set": "zone=example.com, region = x"},
	)
	want := map[string]string{
		"api_token":            "••••••••", // masqué : l'API garde le secret enregistré
		"zone":                 "example.com",
		"service_account_json": `{"a":1,"b":2}`,
		"ttl":                  "60",
		"region":               "x",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, attendu %q", k, got[k], v)
		}
	}
}
