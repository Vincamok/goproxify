// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func pushRetention(t *testing.T, s *Server, p edgews.LogRetentionPayload) error {
	t.Helper()
	msg, err := edgews.NewMessage(1, edgews.TypePushLogRetention, p)
	if err != nil {
		t.Fatal(err)
	}
	return s.handleWSAdminMessage("admin", msg)
}

// La rétention imposée par l'Admin s'applique tout de suite, est gardée chiffrée et survit à un redémarrage sans lui.
func TestPushedLogRetentionSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_LOG_RETENTION_PATH", filepath.Join(dir, "log-retention.gpx"))
	days := func(s *Server, k logstore.Kind) int { return int(s.logStore.Retention(k) / (24 * time.Hour)) }

	g := newLogGateway(t, dir, "secret")
	if days(g, logstore.KindAccess) != 365 || days(g, logstore.KindSystem) != 90 {
		t.Fatalf("défauts = %d / %d", days(g, logstore.KindAccess), days(g, logstore.KindSystem))
	}
	if err := pushRetention(t, g, edgews.LogRetentionPayload{AccessDays: 200, SystemDays: 60}); err != nil {
		t.Fatal(err)
	}
	if days(g, logstore.KindAccess) != 200 || days(g, logstore.KindSystem) != 60 {
		t.Fatalf("après l'ordre = %d / %d", days(g, logstore.KindAccess), days(g, logstore.KindSystem))
	}
	for name, p := range map[string]edgews.LogRetentionPayload{
		"zéro": {AccessDays: 0, SystemDays: 10}, "trop long": {AccessDays: 100000, SystemDays: 10}, "système": {AccessDays: 10, SystemDays: -1},
	} {
		if err := pushRetention(t, g, p); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if days(g, logstore.KindAccess) != 200 {
		t.Fatal("un ordre invalide a changé la rétention")
	}

	// La passerelle redémarre, l'Admin est injoignable : l'ordre est relu, il l'emporte sur edge.json.
	_ = g.logStore.Close()
	g2 := newLogGateway(t, dir, "secret")
	if days(g2, logstore.KindAccess) != 200 || days(g2, logstore.KindSystem) != 60 {
		t.Fatalf("après redémarrage = %d / %d", days(g2, logstore.KindAccess), days(g2, logstore.KindSystem))
	}
}
