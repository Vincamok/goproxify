// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilesEnabled(t *testing.T) {
	if !FilesEnabled() {
		t.Fatal("expected files mode always enabled")
	}
}

func TestClientPublishRoundTrip(t *testing.T) {
	var created, dryrun, promote bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/proxies/revisions", func(w http.ResponseWriter, r *http.Request) {
		created = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "revision": "r1", "host": "a.example.fr", "status": "pending",
			"enabled": true, "config": map[string]any{"id": "p1", "host": "a.example.fr"},
		})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", func(w http.ResponseWriter, r *http.Request) {
		dryrun = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "revision": "r1", "status": "validated",
			"dry_run": map[string]any{"ok": true, "errors": []string{}},
			"config":  map[string]any{"id": "p1"},
		})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", func(w http.ResponseWriter, r *http.Request) {
		promote = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "host": "a.example.fr", "status": "production",
			"enabled": true, "config": map[string]any{"id": "p1", "host": "a.example.fr"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.HTTP = srv.Client()
	env, err := c.Publish(context.Background(), Target{Endpoint: srv.URL, Token: "t"}, "p1", "a.example.fr", true,
		json.RawMessage(`{"id":"p1","host":"a.example.fr","type":"http","backends":[{"url":"http://127.0.0.1:1","weight":1}],"lb":"round_robin"}`),
		"admin")
	if err != nil {
		t.Fatal(err)
	}
	if !created || !dryrun || !promote {
		t.Fatalf("flow incomplete created=%v dry=%v promote=%v", created, dryrun, promote)
	}
	if env.Status != "production" || env.Host != "a.example.fr" {
		t.Fatalf("%+v", env)
	}
}

func TestClientGroupCard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/group-card", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"group": "ha-1", "version": 4, "members": []map[string]string{{"id": "n1", "name": "frontal"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient()
	c.HTTP = srv.Client()

	card, found, err := c.GroupCard(context.Background(), Target{Endpoint: srv.URL, Token: "t"})
	if err != nil || !found || card.Group != "ha-1" || card.Version != 4 || len(card.Members) != 1 {
		t.Fatalf("fiche : %+v found=%v err=%v", card, found, err)
	}
	if _, _, err := c.GroupCard(context.Background(), Target{Endpoint: srv.URL, Token: "mauvais"}); err == nil {
		t.Fatal("un refus d'authentification est une erreur")
	}

	empty := httptest.NewServer(http.NotFoundHandler())
	defer empty.Close()
	c.HTTP = empty.Client()
	if _, found, err := c.GroupCard(context.Background(), Target{Endpoint: empty.URL, Token: "t"}); err != nil || found {
		t.Fatalf("404 = pas de fiche, pas une erreur : found=%v err=%v", found, err)
	}
}
