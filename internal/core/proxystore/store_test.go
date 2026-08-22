// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleConfig(id, host string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"id":   id,
		"host": host,
		"type": "http",
		"backends": []map[string]any{
			{"url": "http://127.0.0.1:8080", "weight": 1},
		},
		"lb": "round_robin",
	})
	return raw
}

func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"App.Example.FR":     "app.example.fr",
		"app/../evil.fr":     "app_.._evil.fr",
		"  spaced host.com ": "spaced_host.com",
		"":                   "",
	}
	for in, want := range cases {
		if got := SanitizeHost(in); got != want {
			t.Errorf("SanitizeHost(%q)=%q want %q", in, got, want)
		}
	}
}

func TestProdFilename(t *testing.T) {
	if got := ProdFilename("app.example.fr", "uuid"); got != "app.example.fr.json" {
		t.Fatalf("got %q", got)
	}
	if got := ProdFilename("", "abc-123"); got != "tcp_abc-123.json" {
		t.Fatalf("tcp got %q", got)
	}
}

func TestRevisionFilename(t *testing.T) {
	got := RevisionFilename("a1b2c3d4", "r7f3")
	if got != "a1b2c3d4--r7f3.json" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteListReadProd(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC().Truncate(time.Second)
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "app.example.fr",
		Enabled:      true,
		Status:        StatusPending, // WriteProd force production
		UpdatedAt:     now,
		Config:        sampleConfig("id-1", "app.example.fr"),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(st.ProdDir(), "app.example.fr.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fichier absent: %v", err)
	}

	list, err := st.ListProd()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}
	if list[0].Status != StatusProduction {
		t.Fatalf("status=%s", list[0].Status)
	}
	if list[0].Revision != "" {
		t.Fatalf("revision should be empty in prod")
	}

	got, err := st.ReadProdByID("id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "app.example.fr" {
		t.Fatalf("host=%s", got.Host)
	}
}

func TestWriteReadRevision(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Revision:      "r1",
		Host:          "app.example.fr",
		Enabled:      true,
		Status:        StatusPending,
		CreatedAt:     &now,
		UpdatedAt:     now,
		CreatedBy:     "admin@example.fr",
		Config:        sampleConfig("id-1", "app.example.fr"),
	}
	if err := st.WriteRevision(env); err != nil {
		t.Fatal(err)
	}

	got, err := st.ReadRevision("id-1", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("status=%s", got.Status)
	}

	revs, err := st.ListRevisions("id-1")
	if err != nil || len(revs) != 1 {
		t.Fatalf("revs=%d err=%v", len(revs), err)
	}

	if err := st.DeleteRevision("id-1", "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReadRevision("id-1", "r1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAtomicWritePreservesOnFailedRename(t *testing.T) {
	// Write twice: second write replaces via rename; first content must not be half-written.
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	cfg1 := sampleConfig("id-1", "app.example.fr")
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "app.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        cfg1,
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	cfg2, _ := json.Marshal(map[string]any{
		"id": "id-1", "host": "app.example.fr", "type": "http",
		"backends": []map[string]any{{"url": "http://10.0.0.2:9", "weight": 1}},
		"lb":       "round_robin",
		"marker":   "second",
	})
	env.Config = cfg2
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	got, err := st.ReadProdByHostID("app.example.fr", "id-1")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got.Config, &m); err != nil {
		t.Fatal(err)
	}
	if m["marker"] != "second" {
		t.Fatalf("config not updated: %v", m)
	}
}

func TestEnvelopeValidate(t *testing.T) {
	env := &Envelope{SchemaVersion: 1, ID: "x", Status: StatusPending, Config: sampleConfig("x", "")}
	if err := env.Validate(); err == nil {
		t.Fatal("expected revision required")
	}
	env.Revision = "r1"
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveProdIfHostChanged(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "old.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        sampleConfig("id-1", "old.example.fr"),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	env.Host = "new.example.fr"
	env.Config = sampleConfig("id-1", "new.example.fr")
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveProdIfHostChanged("old.example.fr", "new.example.fr", "id-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.ProdPath("old.example.fr", "id-1")); !os.IsNotExist(err) {
		t.Fatal("old file should be gone")
	}
	if _, err := st.ReadProdByHostID("new.example.fr", "id-1"); err != nil {
		t.Fatal(err)
	}
}
