// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/portal"
)

// Logins préconfigurés du portail Access (ADR 0025). Le secret est scellé ici, avec la clé publique de la passerelle : l'Admin
// ne reçoit que l'enveloppe chiffrée. Il ne se passe jamais en argument (l'historique du shell le garderait) : fichier ou entrée
// standard.

func runAccessLogins() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "access logins %s : %v\n", action, err)
		os.Exit(1)
	}
	switch action {
	case "list":
		path := "/api/v1/portal/logins"
		if edge := flagValue(args, "-edge", ""); edge != "" {
			path += "?edge=" + url.QueryEscape(edge)
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "pubkey":
		edge := requireFlag(args, "-edge", "Passerelle")
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal/logins/pubkey?edge="+url.QueryEscape(edge), nil, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "create":
		edge := requireFlag(args, "-edge", "Passerelle")
		body := map[string]any{"edge_name": edge, "username": requireFlag(args, "-username", "Identifiant SSH")}
		loginFlags(args, body)
		if err := sealLoginSecret(client, edge, args, body); err != nil {
			fail(err)
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/logins", body, &out, 200, 201); err != nil {
			fail(err)
		}
		printJSON(out)
	case "update":
		id := requireFlag(args, "-id", "ID")
		body := map[string]any{}
		if v := flagValue(args, "-username", ""); v != "" {
			body["username"] = v
		}
		loginFlags(args, body)
		if flagValue(args, "-clear-secret", "") == "true" {
			body["sealed"], body["has_password"], body["has_private_key"] = "", false, false
		} else if flagValue(args, "-password-file", "") != "" || flagValue(args, "-key-file", "") != "" || flagValue(args, "-password-stdin", "") == "true" {
			edge := flagValue(args, "-edge", "")
			if edge == "" {
				var cur struct {
					EdgeName string `json:"edge_name"`
				}
				if _, err := client.DoJSON("GET", "/api/v1/portal/logins/"+url.PathEscape(id), nil, &cur); err != nil {
					fail(err)
				}
				edge = cur.EdgeName
			}
			if err := sealLoginSecret(client, edge, args, body); err != nil {
				fail(err)
			}
		}
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal/logins/"+url.PathEscape(id), body, &out); err != nil {
			fail(err)
		}
		printJSON(out)
	case "delete":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("DELETE", "/api/v1/portal/logins/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fail(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access logins list|pubkey|create|update|delete ...")
		os.Exit(1)
	}
}

// loginFlags lit les options communes à create et update.
func loginFlags(args map[string]string, body map[string]any) {
	if v := flagValue(args, "-name", ""); v != "" {
		body["name"] = v
	}
	if v := flagValue(args, "-all-users", ""); v != "" {
		body["all_users"] = v == "true"
	}
	if v := flagValue(args, "-enabled", ""); v != "" {
		body["enabled"] = v == "true"
	}
	for flag, key := range map[string]string{"-groups": "groups", "-tags": "tags", "-dests": "dest_ids", "-dest-groups": "dest_groups"} {
		if _, set := args[flag]; set {
			body[key] = parseCSVFlag(args, flag)
		}
	}
}

// sealLoginSecret lit le mot de passe et/ou la clé privée, les scelle pour la passerelle et les met dans body.
func sealLoginSecret(client *adminClient, edge string, args map[string]string, body map[string]any) error {
	var secret portal.LoginSecret
	if v := flagValue(args, "-password-file", ""); v != "" {
		raw, err := os.ReadFile(v)
		if err != nil {
			return err
		}
		secret.Password = strings.TrimRight(string(raw), "\r\n")
	}
	if flagValue(args, "-password-stdin", "") == "true" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		secret.Password = strings.TrimRight(string(raw), "\r\n")
	}
	if v := flagValue(args, "-key-file", ""); v != "" {
		raw, err := os.ReadFile(v)
		if err != nil {
			return err
		}
		secret.PrivateKey = string(raw)
	}
	if secret.Empty() {
		return nil // création sans secret : le login existe mais n'est pas proposé tant qu'il n'en a pas
	}
	var pub struct {
		PublicKey string `json:"public_key"`
	}
	if _, err := client.DoJSON("GET", "/api/v1/portal/logins/pubkey?edge="+url.QueryEscape(edge), nil, &pub); err != nil {
		return fmt.Errorf("clé publique de la passerelle : %w", err)
	}
	sealed, err := portal.SealLoginSecret(pub.PublicKey, secret)
	if err != nil {
		return err
	}
	body["sealed"] = sealed
	body["has_password"] = secret.Password != ""
	body["has_private_key"] = secret.PrivateKey != ""
	return nil
}
