// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

func TestGetSIEMStatusMasksTokensAndListsNodes(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := siemcfg.Save(db, siem.Config{Enabled: true, Destinations: []siem.Destination{{ID: "d1", Name: "Splunk", Type: siem.TypeHTTP,
		Address: "https://s.example/in", Headers: map[string]string{"Authorization": "Bearer s3cret"}}}}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: db, SIEMStatus: func() []siemcfg.NodeStatus {
		return []siemcfg.NodeStatus{{NodeName: "gw-a", Destinations: []siem.DestinationStatus{{ID: "d1", Name: "Splunk", State: "retrying", LagSec: 120, LastError: "réponse 503"}}}}
	}}
	raw, _ := json.Marshal(h.toolSIEMStatus())
	out := string(raw)
	if strings.Contains(out, "s3cret") {
		t.Fatal("le jeton est exposé")
	}
	for _, want := range []string{`"gw-a"`, `"retrying"`, `"lag_sec":120`, `"Splunk"`, siemcfg.Masked} {
		if !strings.Contains(out, want) {
			t.Errorf("sortie sans %s : %s", want, out)
		}
	}
	if raw, _ := json.Marshal((&Handler{DB: db}).toolSIEMStatus()); !strings.Contains(string(raw), `"nodes":[]`) {
		t.Errorf("sans état de passerelle : %s", raw)
	}
}
