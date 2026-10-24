// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/threat"
)

// Les rapports de plusieurs passerelles s'additionnent ; une IP vue par deux passerelles n'a qu'une ligne.
func TestSimulationReportsOfSeveralGatewaysAreAdded(t *testing.T) {
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	a := threat.SimReport{Events: 10, Blocked: 4, LegitBlocked: 1, BlockedIPs: 2, ByReason: map[string]int{"errors": 4},
		Bans:   []threat.SimBan{{IP: "1.1.1.1", Reason: "errors", At: at.Add(time.Minute)}},
		TopIPs: []threat.SimIPStat{{IP: "1.1.1.1", Blocked: 3, Reasons: []string{"errors"}, SamplePaths: []string{"/a"}}, {IP: "2.2.2.2", Blocked: 1}}}
	b := threat.SimReport{Events: 5, Blocked: 2, BlockedIPs: 1, ByReason: map[string]int{"errors": 1, "rate": 1},
		Bans:   []threat.SimBan{{IP: "1.1.1.1", Reason: "rate", At: at}},
		TopIPs: []threat.SimIPStat{{IP: "1.1.1.1", Blocked: 2, Reasons: []string{"rate"}, SamplePaths: []string{"/b"}}}}
	sum := emptyReport()
	addReport(&sum, a)
	addReport(&sum, b)
	finishReport(&sum)
	if sum.Events != 15 || sum.Blocked != 6 || sum.LegitBlocked != 1 || sum.BlockedIPs != 3 || sum.ByReason["errors"] != 5 || sum.ByReason["rate"] != 1 {
		t.Errorf("totaux = %+v", sum)
	}
	if len(sum.TopIPs) != 2 || sum.TopIPs[0].IP != "1.1.1.1" || sum.TopIPs[0].Blocked != 5 || len(sum.TopIPs[0].Reasons) != 2 || len(sum.TopIPs[0].SamplePaths) != 2 {
		t.Errorf("IP les plus touchées = %+v", sum.TopIPs)
	}
	if len(sum.Bans) != 2 || sum.Bans[0].Reason != "rate" {
		t.Errorf("bans dans l'ordre du temps = %+v", sum.Bans)
	}
}
