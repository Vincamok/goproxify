// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/siem"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// fakeSIEM reçoit des lots NDJSON et peut être coupé.
type fakeSIEM struct {
	srv  *httptest.Server
	mu   sync.Mutex
	down bool
	ids  []string
	auth string
}

func newFakeSIEM(t *testing.T) *fakeSIEM {
	t.Helper()
	f := &fakeSIEM{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "coupé", http.StatusServiceUnavailable)
			return
		}
		f.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var rec struct {
				ID string `json:"id"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil && rec.ID != "" {
				f.ids = append(f.ids, rec.ID)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSIEM) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func (f *fakeSIEM) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

func waitSIEM(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// L'exporteur est autonome : configuré une fois par l'Admin, il continue après un redémarrage de la passerelle sans
// l'Admin, reprend où il s'était arrêté et livre ce que la coupure du SIEM a retardé, sans rejouer le passé.
func TestSIEMExporterSurvivesGatewayRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_SIEM_CONFIG_PATH", filepath.Join(dir, "siem-config.gpx"))
	t.Setenv("GPX_SIEM_STATE_PATH", filepath.Join(dir, "siem-state.gpx"))
	siemSrv := newFakeSIEM(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g1 := newLogGateway(t, dir, "secret")
	g1.cfg.Identity.NodeName = "gw-a"
	g1.startSIEM(ctx)
	cfg := siem.Config{Enabled: true, Destinations: []siem.Destination{{ID: "d1", Name: "Splunk", Type: siem.TypeHTTP, Address: siemSrv.srv.URL,
		Headers: map[string]string{"Authorization": "Bearer jeton-secret-42"}}}}
	msg, err := edgews.NewMessage(1, edgews.TypePushSIEMConfig, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := g1.handleWSAdminMessage("admin", msg); err != nil {
		t.Fatal(err)
	}

	serveOne(t, g1, "198.51.100.10")
	serveOne(t, g1, "198.51.100.11")
	waitSIEM(t, "les deux premiers accès", func() bool { return len(siemSrv.received()) == 2 })
	if siemSrv.auth != "Bearer jeton-secret-42" {
		t.Errorf("en-tête transmis : %q", siemSrv.auth)
	}
	raw, err := os.ReadFile(siemConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "jeton-secret-42") || strings.Contains(string(raw), "Splunk") {
		t.Error("la copie locale de la config est en clair")
	}

	// Le SIEM tombe, puis la passerelle redémarre : l'Admin n'est plus là pour renvoyer la config.
	siemSrv.setDown(true)
	serveOne(t, g1, "198.51.100.12")
	serveOne(t, g1, "198.51.100.13")
	serveOne(t, g1, "198.51.100.14")
	g1.logStore.Flush()
	waitSIEM(t, "l'état en échec", func() bool {
		st := g1.siemExporter.Status()
		return len(st) == 1 && st[0].State == "retrying"
	})
	g1.siemExporter.Close()
	_ = g1.logStore.Close()
	if n := len(siemSrv.received()); n != 2 {
		t.Fatalf("%d lignes reçues pendant la coupure", n)
	}

	g2 := newLogGateway(t, dir, "secret")
	g2.cfg.Identity.NodeName = "gw-a"
	siemSrv.setDown(false)
	g2.startSIEM(ctx)
	waitSIEM(t, "les trois accès retardés", func() bool { return len(siemSrv.received()) == 5 })
	time.Sleep(300 * time.Millisecond)
	ids := siemSrv.received()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("ligne livrée deux fois : %s", id)
		}
		seen[id] = true
	}
	if len(ids) != 5 {
		t.Fatalf("lignes reçues : %v", ids)
	}
	if st := g2.siemExporter.Status(); len(st) != 1 || st[0].LagSec != 0 {
		t.Errorf("état après reprise : %+v", st)
	}
	g2.siemExporter.Close()
}

// Une configuration invalide poussée par l'Admin est refusée et ne remplace pas la copie locale.
func TestSIEMInvalidConfigIsRejected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_SIEM_CONFIG_PATH", filepath.Join(dir, "siem-config.gpx"))
	t.Setenv("GPX_SIEM_STATE_PATH", filepath.Join(dir, "siem-state.gpx"))
	g := newLogGateway(t, dir, "secret")
	g.startSIEM(context.Background())
	defer g.siemExporter.Close()
	msg, _ := edgews.NewMessage(1, edgews.TypePushSIEMConfig, siem.Config{Enabled: true, Destinations: []siem.Destination{{ID: "x", Name: "n", Type: "kafka", Address: "h:1"}}})
	if err := g.handleWSAdminMessage("admin", msg); err == nil {
		t.Fatal("une destination de type inconnu doit être refusée")
	}
	if _, err := os.Stat(siemConfigPath()); err == nil {
		t.Error("la configuration invalide a été enregistrée")
	}
	if len(g.siemExporter.Status()) != 0 {
		t.Error("une destination invalide est active")
	}
}
