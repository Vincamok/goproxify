// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package gdpr

import (
	"bytes"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestEnsureKeyIsStable(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	k1, err := EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 || !bytes.Equal(k1, k2) {
		t.Fatalf("clé instable ou de mauvaise taille : %d octets, égales=%v", len(k1), bytes.Equal(k1, k2))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	c1, err := Encrypt(key, "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := Encrypt(key, "203.0.113.42")
	if c1 == c2 {
		t.Fatal("deux chiffrés identiques : nonce non aléatoire")
	}
	if got, err := Decrypt(key, c1); err != nil || got != "203.0.113.42" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	if _, err := Decrypt(bytes.Repeat([]byte{8}, 32), c1); err == nil {
		t.Fatal("déchiffrement accepté avec une autre clé")
	}
}

func TestIPIndex(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	same := [][2]string{
		{"203.0.113.42", " 203.0.113.42 "},
		{"203.0.113.42", "::ffff:203.0.113.42"},
		{"2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001"},
		{"fe80::1", "fe80::1%eth0"},
	}
	for _, p := range same {
		if IPIndex(key, p[0]) != IPIndex(key, p[1]) {
			t.Errorf("%q et %q : empreintes différentes", p[0], p[1])
		}
	}
	if IPIndex(key, "203.0.113.42") == IPIndex(key, "203.0.113.43") {
		t.Error("deux IP différentes : même empreinte")
	}
	if IPIndex(key, "203.0.113.42") == IPIndex(bytes.Repeat([]byte{8}, 32), "203.0.113.42") {
		t.Error("l'empreinte ne dépend pas de la clé")
	}
}
