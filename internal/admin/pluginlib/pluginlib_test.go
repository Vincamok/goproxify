// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package pluginlib

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/plugins"
)

// Chaque plugin intégré se charge dans le vrai moteur : module valide, contrat respecté, empreinte exacte.
func TestLibraryEntriesLoad(t *testing.T) {
	all := All()
	if len(all) < 4 {
		t.Fatalf("%d plugins intégrés, attendu au moins 4", len(all))
	}
	for _, e := range all {
		if e.Manifest.Name != e.Name || e.Version == "" || e.Description == "" {
			t.Errorf("%s : entrée incomplète", e.Name)
		}
		p, err := plugins.Load(context.Background(), e.Manifest, e.Wasm, e.SHA256, nil)
		if err != nil {
			t.Errorf("%s : %v", e.Name, err)
			continue
		}
		p.Close(context.Background())
	}
}

// Les copies embarquées sont celles des exemples : sans ce test, corriger un exemple sans recopier ici livrerait
// l'ancien module.
func TestLibraryMatchesExamples(t *testing.T) {
	root := filepath.Join("..", "..", "..", "examples", "plugins")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("exemples absents : %v", err)
	}
	for _, e := range All() {
		wasm, err := os.ReadFile(filepath.Join(root, e.Name, e.Name+".wasm"))
		if err != nil {
			t.Errorf("%s : %v", e.Name, err)
			continue
		}
		if !bytes.Equal(wasm, e.Wasm) {
			t.Errorf("%s : le module embarqué diffère de examples/plugins/%s (recopier le .wasm dans internal/admin/pluginlib/packages)", e.Name, e.Name)
		}
		man, _ := os.ReadFile(filepath.Join(root, e.Name, "manifest.json"))
		emb, _ := os.ReadFile(filepath.Join("packages", e.Name, "manifest.json"))
		if !bytes.Equal(bytes.TrimSpace(bytes.ReplaceAll(man, []byte("\r\n"), []byte("\n"))), bytes.TrimSpace(bytes.ReplaceAll(emb, []byte("\r\n"), []byte("\n")))) {
			t.Errorf("%s : le manifeste embarqué diffère de celui de l'exemple", e.Name)
		}
	}
}
