// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"testing"
	"time"
)

func TestAgentTokenTTLIgnoresTheProcessTimezone(t *testing.T) {
	// Processus à UTC-5 : l'échéance à l'heure locale, comparée en texte à CURRENT_TIMESTAMP (UTC),
	// était déjà dépassée.
	prev := time.Local
	time.Local = time.FixedZone("EST", -5*3600)
	t.Cleanup(func() { time.Local = prev })
	s := openTestStore(t)
	if _, _, err := s.Create("agent-1", RoleAgent, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !s.HasActiveAgent("agent-1") {
		t.Fatal("un token agent valable 1 h doit être actif")
	}
}
