// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Sources de destinations du portail Access (ADR 0024) : `access sources` configure les plateformes interrogées par la
// passerelle ; `access candidates` traite les machines qu'elles ont découvertes.

func runAccessSources() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "access sources %s : %v\n", action, err)
		os.Exit(1)
	}
	switch action {
	case "types":
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal/dest-sources/types", nil, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "list":
		path := "/api/v1/portal/dest-sources"
		if edge := flagValue(args, "-edge", ""); edge != "" {
			path += "?edge=" + url.QueryEscape(edge)
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "create":
		body := map[string]any{
			"edge_name":  requireFlag(args, "-edge", "Passerelle"),
			"type":       requireFlag(args, "-type", "Type de source (voir « access sources types »)"),
			"name":       requireFlag(args, "-name", "Nom"),
			"config":     sourceConfig(args),
			"extra_tags": parseTagsFlag(args),
		}
		if v := flagValue(args, "-interval", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintln(os.Stderr, "-interval invalide (secondes)")
				os.Exit(1)
			}
			body["interval_s"] = n
		}
		if flagValue(args, "-auto-publish", "") == "true" {
			body["auto_publish"] = true
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/dest-sources", body, &out, 200, 201); err != nil {
			fail(err)
		}
		printJSON(out)
	case "update":
		id := requireFlag(args, "-id", "ID")
		body := map[string]any{}
		if v := flagValue(args, "-name", ""); v != "" {
			body["name"] = v
		}
		if cfg := sourceConfig(args); len(cfg) > 0 {
			body["config"] = cfg
		}
		if v := flagValue(args, "-enabled", ""); v != "" {
			body["enabled"] = v == "true"
		}
		if v := flagValue(args, "-auto-publish", ""); v != "" {
			body["auto_publish"] = v == "true"
		}
		if v := flagValue(args, "-tags", ""); v != "" {
			body["extra_tags"] = parseTagsFlag(args)
		}
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal/dest-sources/"+url.PathEscape(id), body, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "delete":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("DELETE", "/api/v1/portal/dest-sources/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fail(err)
		}
		fmt.Println("ok")
	case "test":
		body := map[string]any{
			"edge_name": requireFlag(args, "-edge", "Passerelle"),
			"type":      requireFlag(args, "-type", "Type de source"),
			"config":    sourceConfig(args),
			"source_id": flagValue(args, "-id", ""),
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/dest-sources/test", body, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "sync":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("POST", "/api/v1/portal/dest-sources/"+url.PathEscape(id)+"/sync", nil, nil, 200, 202); err != nil {
			fail(err)
		}
		fmt.Println("synchronisation demandée")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access sources types|list|create|update|delete|test|sync ...")
		os.Exit(1)
	}
}

// sourceConfig lit la configuration d'une source : -json '{"url":…}' (JSON) et/ou -set clé=valeur (répétable via
// virgules). Les secrets se passent par -set ou -config-file pour ne pas rester dans l'historique du shell.
func sourceConfig(args map[string]string) map[string]any {
	cfg := map[string]any{}
	if path := flagValue(args, "-config-file", ""); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-config-file : %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "-config-file : JSON invalide : %v\n", err)
			os.Exit(1)
		}
	}
	if raw := flagValue(args, "-json", ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "-json : JSON invalide : %v\n", err)
			os.Exit(1)
		}
	}
	for _, kv := range strings.Split(flagValue(args, "-set", ""), ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "-set : %q attendu sous la forme clé=valeur\n", kv)
			os.Exit(1)
		}
		switch v {
		case "true":
			cfg[k] = true
		case "false":
			cfg[k] = false
		default:
			cfg[k] = v
		}
	}
	return cfg
}

func runAccessCandidates() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "access candidates %s : %v\n", action, err)
		os.Exit(1)
	}
	switch action {
	case "list":
		q := url.Values{}
		for flag, key := range map[string]string{"-edge": "edge", "-state": "state", "-source": "source"} {
			if v := flagValue(args, flag, ""); v != "" {
				q.Set(key, v)
			}
		}
		path := "/api/v1/portal/dest-candidates"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "publish":
		ids := strings.Split(requireFlag(args, "-ids", "Identifiants de candidates, séparés par des virgules"), ",")
		body := map[string]any{"ids": ids, "tags": parseTagsFlag(args)}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/dest-candidates/publish", body, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "ignore", "restore":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("POST", "/api/v1/portal/dest-candidates/"+url.PathEscape(id)+"/"+action, nil, nil, 200, 204); err != nil {
			fail(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access candidates list|publish|ignore|restore ...")
		os.Exit(1)
	}
}
