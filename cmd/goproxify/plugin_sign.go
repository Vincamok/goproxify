// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/plugins"
)

func runPluginKeygen() {
	args := parseFlags(os.Args[3:])
	out := flagValue(args, "-out", "")
	if out == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify plugin keygen -out <préfixe>")
		os.Exit(1)
	}
	pub, priv, err := plugins.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	// La clé privée n'est jamais écrasée : la perdre rend les plugins déjà signés invérifiables.
	if err := writeNewFile(out+".key", base64.StdEncoding.EncodeToString(priv.Seed())+"\n", 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	if err := writeNewFile(out+".pub", pubB64+"\n", 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Clé privée : %s.key (à garder secrète)\nClé publique : %s.pub\nIdentifiant : %s\nClé publique (base64) : %s\n", out, out, plugins.KeyID(pub), pubB64)
}

func writeNewFile(path, content string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func runPluginSign() {
	args := parseFlags(os.Args[3:])
	keyFile, manifestFile, wasmFile := flagValue(args, "-key", ""), flagValue(args, "-manifest", ""), flagValue(args, "-wasm", "")
	if keyFile == "" || manifestFile == "" || wasmFile == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify plugin sign -key <fichier.key> -manifest <plugin.json> -wasm <plugin.wasm>")
		os.Exit(1)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lecture de la clé : %v\n", err)
		os.Exit(1)
	}
	priv, err := plugins.ParsePrivateKey(strings.TrimSpace(string(kb)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	mb, err := os.ReadFile(manifestFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lecture du manifeste : %v\n", err)
		os.Exit(1)
	}
	var m plugins.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		fmt.Fprintf(os.Stderr, "manifeste JSON invalide : %v\n", err)
		os.Exit(1)
	}
	wasm, err := os.ReadFile(wasmFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lecture du module : %v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(wasm)
	sig, err := plugins.Sign(priv, m, hex.EncodeToString(sum[:]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "manifeste invalide : %v\n", err)
		os.Exit(1)
	}
	fmt.Println(sig)
}

func runPluginKeys() {
	sub := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	switch sub {
	case "list", "ls", "":
		var keys []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/plugin-keys", nil, &keys); err != nil {
			fmt.Fprintf(os.Stderr, "plugin keys list : %v\n", err)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Println("(aucune clé de confiance : la signature des plugins est facultative)")
			return
		}
		for _, k := range keys {
			fmt.Printf("%s  %s\n", k.ID, k.Name)
		}
	case "add":
		name, pub := flagValue(args, "-name", ""), flagValue(args, "-public-key", "")
		if name == "" || pub == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin keys add -name <nom> -public-key <base64>")
			os.Exit(1)
		}
		var k struct {
			ID string `json:"id"`
		}
		if _, err := client.DoJSON("POST", "/api/v1/plugin-keys", map[string]string{"name": name, "public_key": pub}, &k, 201); err != nil {
			fmt.Fprintf(os.Stderr, "plugin keys add : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Clé %s enregistrée : les plugins installés ou remplacés devront être signés.\n", k.ID)
	case "delete", "rm":
		id := flagValue(args, "-id", "")
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin keys delete -id <id>")
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/plugin-keys/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "plugin keys delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Clé %s retirée (les plugins déjà installés ne sont pas retirés).\n", id)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande plugin keys inconnue : %q\n", sub)
		os.Exit(1)
	}
}
