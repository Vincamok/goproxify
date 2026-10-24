// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"testing"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
)

// Une passerelle qui n'a pas répondu est écartée des lectures pendant edgeproxy.EdgeRetry : au moins un des essais de
// rattrapage doit tomber après ce délai, sans quoi tous échouent sur ErrEdgeDown.
func TestSyncProxiesRetriesOutlastTheLivenessWindow(t *testing.T) {
	if len(syncProxiesRetryWaits) < 2 {
		t.Fatalf("plusieurs essais attendus : %v", syncProxiesRetryWaits)
	}
	var elapsed int64
	late := 0
	for _, w := range syncProxiesRetryWaits {
		elapsed += int64(w)
		if int64(w) > int64(edgeproxy.EdgeRetry) {
			late++
		}
	}
	if late == 0 {
		t.Fatalf("aucun délai ne dépasse %v : %v", edgeproxy.EdgeRetry, syncProxiesRetryWaits)
	}
	if elapsed < int64(edgeproxy.EdgeRetry) {
		t.Fatalf("la durée totale doit dépasser la fenêtre : %v", syncProxiesRetryWaits)
	}
}
