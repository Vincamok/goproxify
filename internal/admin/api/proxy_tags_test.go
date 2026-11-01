// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestValidateProxyIdentity(t *testing.T) {
	ok := &router.Route{Name: "alpha-1", Labels: map[string]string{"env": "prod"}}
	if err := ValidateProxyIdentity(ok); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxyIdentity(&router.Route{}); err != nil {
		t.Fatalf("nom et étiquettes sont facultatifs : %v", err)
	}
	for name, r := range map[string]*router.Route{
		"nom trop long":      {Name: strings.Repeat("a", 129)},
		"nom avec contrôle":  {Name: "a\nb"},
		"clé en majuscules":  {Labels: map[string]string{"Env": "prod"}},
		"valeur avec espace": {Labels: map[string]string{"env": "pro d"}},
	} {
		if err := ValidateProxyIdentity(r); err == nil {
			t.Errorf("%s : devrait être refusé", name)
		}
	}
}

func TestLabelChange(t *testing.T) {
	if got := LabelChange(nil, nil); got != "" {
		t.Fatalf("aucun changement : %q", got)
	}
	if got := LabelChange(map[string]string{"env": "prod"}, map[string]string{"env": "prod"}); got != "" {
		t.Fatalf("identiques : %q", got)
	}
	got := LabelChange(map[string]string{"env": "test", "old": "x"}, map[string]string{"env": "prod", "projet": "alpha"})
	for _, want := range []string{"+projet=alpha", "env: test → prod", "-old=x"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q absent de %q", want, got)
		}
	}
}
