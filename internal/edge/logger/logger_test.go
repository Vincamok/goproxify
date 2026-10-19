// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDynamicLoggerForwarder(t *testing.T) {
	dl := New("info", "json", "")
	var (
		mu  sync.Mutex
		got []ShipEntry
	)
	done := make(chan struct{})
	dl.SetNodeName("edge-test")
	dl.SetForwarder(func(batch []ShipEntry) {
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		select {
		case <-done:
		default:
			close(done)
		}
	})

	dl.Info("hello system", "domain", "example.com", "err", "none")

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("timeout waiting for system log ship")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("expected shipped entries")
	}
	e := got[0]
	if e.Component != "edge" {
		t.Errorf("component=%q want edge", e.Component)
	}
	if e.Status != 0 {
		t.Errorf("status=%d want 0 (system)", e.Status)
	}
	if e.NodeName != "edge-test" {
		t.Errorf("node_name=%q want edge-test", e.NodeName)
	}
	if e.Domain != "example.com" {
		t.Errorf("domain=%q want example.com", e.Domain)
	}
	if e.Method != "" || e.Path != "" {
		t.Errorf("system log must not have method/path: %q %q", e.Method, e.Path)
	}
	if e.Message == "" || e.Message[:5] != "hello" {
		t.Errorf("message=%q", e.Message)
	}
}

// Le journal d'accès texte des routes doublonne le journal d'accès structuré déjà expédié : écrit avec
// LocalOnly, il reste sur la passerelle (fichier, sortie) et ne part pas vers l'Admin.
func TestLocalOnlyLinesAreNotShipped(t *testing.T) {
	dl := New("info", "json", "")
	var (
		mu  sync.Mutex
		got []ShipEntry
	)
	dl.SetNodeName("edge-test")
	dl.SetForwarder(func(batch []ShipEntry) {
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
	})

	dl.Logger().InfoContext(LocalOnly(context.Background()), "ligne locale")
	dl.Logger().InfoContext(context.Background(), "ligne expédiée")

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0].Message, "ligne expédiée") {
		t.Fatalf("lignes expédiées : %+v, attendu uniquement « ligne expédiée »", got)
	}
}
