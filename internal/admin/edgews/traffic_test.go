// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"testing"
	"time"
)

// Le débit annoncé est celui de la dernière minute de la passerelle ; une passerelle muette n'a plus de débit.
func TestRecentTrafficExpiresWhenTheGatewayGoesQuiet(t *testing.T) {
	m := &Manager{}
	m.handleEdgeTraffic(json.RawMessage(`{"node_name":"gw-a","window_sec":60,"requests":120,"blocked":6,"errors":3}`))
	if req, blocked, errs, ok := m.RecentTraffic("gw-a"); !ok || req != 120 || blocked != 6 || errs != 3 {
		t.Fatalf("débit = %d/%d/%d ok=%v", req, blocked, errs, ok)
	}
	if _, _, _, ok := m.RecentTraffic("gw-b"); ok {
		t.Error("une passerelle inconnue n'a pas de débit")
	}
	m.traffic.mu.Lock()
	s := m.traffic.byNode["gw-a"]
	s.at = time.Now().Add(-2 * trafficFresh)
	m.traffic.byNode["gw-a"] = s
	m.traffic.mu.Unlock()
	if _, _, _, ok := m.RecentTraffic("gw-a"); ok {
		t.Error("un débit périmé ne doit pas être servi")
	}
	m.handleEdgeTraffic(json.RawMessage(`pas du json`))
	m.handleEdgeTraffic(json.RawMessage(`{"requests":5}`))
}
