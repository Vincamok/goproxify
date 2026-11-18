// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"strings"
	"testing"
)

// Le gestionnaire WebSocket n'émet d'alerte (backend hors service, ban Ephor, SIEM, trafic, événements d'Agent…) que si le
// moteur lui est confié ; sans cet appel, tous ces chemins restent muets sans qu'aucune erreur ne le dise.
func TestWebSocketManagerIsGivenTheAlertEngine(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "manager.SetAlertEngine(s.alertingEngine)") {
		t.Fatal("server.go ne confie pas le moteur d'alertes au gestionnaire WebSocket")
	}
}
