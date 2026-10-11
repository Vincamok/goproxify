// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package pluginlib porte les plugins livrés avec l'Admin : des exemples compilés (examples/plugins) que l'on installe
// d'un clic depuis la page Plugins, sans dépôt ni téléchargement. Sans eux, un Admin neuf n'offrait aucun plugin :
// le catalogue ne montre que ce que sert un dépôt, et aucun n'est configuré à l'installation.
//
// Ce sont les mêmes octets que ceux des exemples (TestLibraryMatchesExamples le vérifie) : ils font confiance à
// l'Admin qui les embarque, au même titre que son propre binaire, et n'exigent donc pas de signature.
package pluginlib

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"sort"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/plugins"
)

//go:embed packages
var packages embed.FS

// RepoID est l'identifiant du dépôt intégré dans le catalogue et l'installation depuis un dépôt.
const RepoID = "builtin"

// RepoName est son nom affiché.
const RepoName = "Exemples intégrés"

// Entry est un plugin livré avec l'Admin.
type Entry struct {
	Name        string
	Version     string
	Description string
	Manifest    plugins.Manifest
	Wasm        []byte
	SHA256      string
}

var (
	once    sync.Once
	entries []Entry
)

func load() {
	dirs, err := fs.ReadDir(packages, "packages")
	if err != nil {
		return
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		raw, err := packages.ReadFile("packages/" + name + "/manifest.json")
		if err != nil {
			continue
		}
		var m plugins.Manifest
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		wasm, err := packages.ReadFile("packages/" + name + "/" + name + ".wasm")
		if err != nil {
			continue
		}
		desc, _ := packages.ReadFile("packages/" + name + "/description.txt")
		sum := sha256.Sum256(wasm)
		entries = append(entries, Entry{
			Name: m.Name, Version: m.Version, Description: string(desc),
			Manifest: m, Wasm: wasm, SHA256: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
}

// All retourne les plugins intégrés, triés par nom.
func All() []Entry {
	once.Do(load)
	return entries
}

// Get retourne un plugin intégré.
func Get(name string) (Entry, bool) {
	for _, e := range All() {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}
