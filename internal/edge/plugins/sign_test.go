// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/base64"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	m := manifest()
	sig, err := Sign(priv, m, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, m, "abc123", sig) {
		t.Fatal("signature valide refusée")
	}
	// Le manifeste est couvert en entier : un manifeste plus permissif ne passe pas.
	for name, mutate := range map[string]func(*Manifest){
		"on_error": func(m *Manifest) { m.OnError = OnErrorAllow },
		"limites":  func(m *Manifest) { m.Limits.TimeoutMs = 900 },
		"version":  func(m *Manifest) { m.Version = "2.0.0" },
		"hooks":    func(m *Manifest) { m.Hooks = []string{HookRequest, HookResponse} },
		"nom":      func(m *Manifest) { m.Name = "autre" },
	} {
		other := manifest()
		mutate(&other)
		if Verify(pub, other, "abc123", sig) {
			t.Errorf("%s : signature acceptée pour un manifeste modifié", name)
		}
	}
	if Verify(pub, m, "autre-empreinte", sig) {
		t.Error("signature acceptée pour un autre module")
	}
	otherPub, _, _ := GenerateKey()
	if Verify(otherPub, m, "abc123", sig) {
		t.Error("signature acceptée avec une autre clé")
	}
	for _, bad := range []string{"", "pas-du-base64!", base64.StdEncoding.EncodeToString([]byte("court"))} {
		if Verify(pub, m, "abc123", bad) {
			t.Errorf("signature %q acceptée", bad)
		}
	}
	// Les valeurs par défaut du manifeste ne changent pas la signature.
	explicit := manifest()
	explicit.OnError = OnErrorDeny
	explicit.Limits = Limits{MemoryPages: DefaultMemoryPages, TimeoutMs: DefaultTimeoutMs}
	if !Verify(pub, explicit, "abc123", sig) {
		t.Error("manifeste explicite équivalent refusé")
	}
}

func TestKeyParsing(t *testing.T) {
	pub, priv, _ := GenerateKey()
	got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || KeyID(got) != KeyID(pub) || len(KeyID(pub)) != 16 {
		t.Fatalf("clé publique : %v", err)
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Error("clé trop courte acceptée")
	}
	seed := priv.Seed()
	fromSeed, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(seed))
	if err != nil || string(fromSeed) != string(priv) {
		t.Errorf("graine : %v", err)
	}
	if _, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(priv)); err != nil {
		t.Errorf("clé complète : %v", err)
	}
	if _, err := ParsePrivateKey("AAAA"); err == nil {
		t.Error("clé privée trop courte acceptée")
	}
}
