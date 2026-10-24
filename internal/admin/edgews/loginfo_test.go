// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"testing"
	"time"

	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestLogInfoKeepsTheLatestRetentionPerGatewayAndFlagsSilentOnes(t *testing.T) {
	m := &Manager{}
	send := func(p edgeWS.LogInfoPayload) {
		raw, _ := json.Marshal(p)
		m.handleLogInfo(raw)
	}
	send(edgeWS.LogInfoPayload{NodeName: "gw-a", AccessDays: 365, SystemDays: 90})
	send(edgeWS.LogInfoPayload{NodeName: "gw-b", AccessDays: 30, SystemDays: 30})
	send(edgeWS.LogInfoPayload{NodeName: "gw-a", AccessDays: 200, SystemDays: 60}) // l'annonce suivante remplace
	m.handleLogInfo([]byte(`{"access_days":5}`))                                   // sans nom : ignoré
	m.handleLogInfo([]byte(`pas du json`))

	got := map[string]int{}
	for _, i := range m.LogInfo() {
		got[i.NodeName] = i.AccessDays
		if i.Stale || i.ReportedAt == "" {
			t.Errorf("%s : %+v", i.NodeName, i)
		}
	}
	if len(got) != 2 || got["gw-a"] != 200 || got["gw-b"] != 30 {
		t.Fatalf("rétention annoncée = %v", got)
	}
	m.logInfo.mu.Lock()
	m.logInfo.at["gw-b"] = time.Now().Add(-5 * time.Minute)
	m.logInfo.mu.Unlock()
	for _, i := range m.LogInfo() {
		if (i.NodeName == "gw-b") != i.Stale {
			t.Errorf("%s : stale = %v", i.NodeName, i.Stale)
		}
	}
}
