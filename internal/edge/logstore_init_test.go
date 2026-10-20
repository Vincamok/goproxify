// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// newLogGateway construit une passerelle sur le volume dir ; deux appels sur le même dir simulent un redémarrage.
func newLogGateway(t *testing.T, dir, secret string) *Server {
	t.Helper()
	t.Setenv("GPX_LOG_IP_KEY_PATH", filepath.Join(dir, "log-ip-key.gpx"))
	cfg := &config.EdgeConfig{}
	cfg.Engine.LogStoreDir = filepath.Join(dir, "logs")
	s := &Server{
		cfg:       cfg,
		log:       edgelog.New("error", "text", ""),
		accessLog: edgelog.NewAccessLogger(),
		cache:     edgecache.New(filepath.Join(dir, "edge-cache.gpx"), secret),
	}
	s.initLogStore()
	t.Cleanup(func() {
		if s.logStore != nil {
			_ = s.logStore.Close()
		}
	})
	return s
}

func serveOne(t *testing.T, s *Server, ip string) {
	t.Helper()
	h := s.accessLog.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	req.RemoteAddr = ip + ":4242"
	h.ServeHTTP(httptest.NewRecorder(), req)
}

func accessRows(t *testing.T, s *Server, n int) []logstore.Row {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.logStore.Flush()
		rows, err := s.logStore.ReadAfter(logstore.KindAccess, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == n || time.Now().After(deadline) {
			if len(rows) != n {
				t.Fatalf("%d lignes d'accès, attendu %d", len(rows), n)
			}
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// La clé qui pseudonymise l'IP réelle survit à un redémarrage sans l'Admin : sans elle, les lignes déjà écrites
// ne se révéleraient plus.
func TestLogIPKeySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	s := newLogGateway(t, dir, "cle-passerelle")
	s.accessLog.SetIPProtection(false, true)
	serveOne(t, s, "203.0.113.42")
	rows := accessRows(t, s, 1)
	if !rows[0].Pseudonymized || rows[0].IP != "203.0.113.0" {
		t.Fatalf("ligne attendue pseudonymisée : %+v", rows[0])
	}
	_ = s.logStore.Close()

	raw, err := os.ReadFile(filepath.Join(dir, "log-ip-key.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"key"`)) {
		t.Fatal("la clé de pseudonymisation est écrite en clair sur le volume")
	}

	restarted := newLogGateway(t, dir, "cle-passerelle")
	got, err := restarted.logStore.RevealIP(logstore.KindAccess, rows[0].ID)
	if err != nil || got != "203.0.113.42" {
		t.Fatalf("après redémarrage RevealIP = %q, %v", got, err)
	}
}

// Une clé illisible n'est jamais remplacée : la passerelle sert et journalise, mais sans garder l'IP réelle.
func TestUnreadableLogIPKeyIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	first := newLogGateway(t, dir, "ancien-secret")
	first.accessLog.SetIPProtection(false, true)
	serveOne(t, first, "203.0.113.42")
	accessRows(t, first, 1)
	_ = first.logStore.Close()
	before, err := os.ReadFile(filepath.Join(dir, "log-ip-key.gpx"))
	if err != nil {
		t.Fatal(err)
	}

	changed := newLogGateway(t, dir, "nouveau-secret")
	if changed.logStore == nil {
		t.Fatal("la passerelle doit garder sa base de logs même sans clé")
	}
	changed.accessLog.SetIPProtection(false, true)
	serveOne(t, changed, "198.51.100.9")
	rows := accessRows(t, changed, 2)
	if rows[1].Pseudonymized {
		t.Fatal("sans clé lisible, aucune IP réelle ne doit être gardée")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "log-ip-key.gpx"))
	if !bytes.Equal(before, after) {
		t.Fatal("la clé illisible a été écrasée : les lignes pseudonymisées seraient perdues pour toujours")
	}
}

func TestEraseIPsRemovesTheIPFromTheLocalLogs(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	serveOne(t, s, "203.0.113.42")
	s.accessLog.SetIPProtection(false, true)
	serveOne(t, s, "203.0.113.42") // pseudonymisée : visible tronquée, réelle chiffrée
	s.accessLog.SetIPProtection(false, false)
	serveOne(t, s, "198.51.100.9")
	accessRows(t, s, 3)

	s.applyEraseIPs([]edgews.EraseEntry{{IP: ""}, {IP: "203.0.113.42"}})

	rows := accessRows(t, s, 1)
	if rows[0].IP != "198.51.100.9" {
		t.Fatalf("il devait rester la ligne de l'autre IP : %+v", rows[0])
	}
}
