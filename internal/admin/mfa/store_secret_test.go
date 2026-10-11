// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestListedMethodsNeverExposeSecret(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertMethod(ctx, "u1", MethodTOTP, map[string]string{"secret": "JBSWY3DPEHPK3PXP"}, true); err != nil {
		t.Fatal(err)
	}
	methods, err := s.ListMethods(ctx, "u1")
	if err != nil || len(methods) != 1 {
		t.Fatalf("methods=%v err=%v", methods, err)
	}
	b, _ := json.Marshal(methods)
	if strings.Contains(string(b), "JBSWY3DPEHPK3PXP") || strings.Contains(string(b), "config") {
		t.Fatalf("la sérialisation expose la configuration : %s", b)
	}
	var cfg struct{ Secret string }
	if err := s.GetMethodConfig(ctx, "u1", MethodTOTP, &cfg); err != nil || cfg.Secret == "" {
		t.Fatalf("la configuration doit rester lisible côté serveur : %v %v", cfg, err)
	}
}
