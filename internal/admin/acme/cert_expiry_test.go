// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rulesengine"
)

func TestSavedCertExpiryIsSeenByRenewalAndRules(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	m := New(d, slog.Default(), nil, nil, "")
	notAfter := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second) // comme leaf.NotAfter
	if err := m.saveCertMeta("a.example", "letsencrypt", notAfter, []byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	if got := m.domainsToRenew(context.Background()); len(got) != 1 || got[0] != "a.example" {
		t.Errorf("à renouveler (≤ 30 j) : %v", got)
	}
	// La règle lit expires_at via julianday(), qui renvoie NULL pour un time.Time lié tel quel (t.String()).
	matched, detail, err := rulesengine.New(d, slog.Default(), rulesengine.Deps{}).EvalCondition(context.Background(),
		rulesengine.Condition{Type: rulesengine.CondCertExpiring, DaysLeft: 15})
	if err != nil || !matched || detail["domain"] != "a.example" {
		t.Fatalf("cert_expiring (15 j) doit voir le certificat ACME qui expire dans 10 j : %v %v %v", matched, detail, err)
	}
}
