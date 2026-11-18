// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

func TestResolve(t *testing.T) {
	var calls atomic.Int32
	answers := map[string][]net.IPAddr{
		"vm-docker": {{IP: net.ParseIP("fe80::1")}, {IP: net.ParseIP("192.168.10.91")}},
	}
	fail := false
	defer SetLookup(func(_ context.Context, h string) ([]net.IPAddr, error) {
		calls.Add(1)
		if fail {
			return nil, errors.New("timeout")
		}
		if a, ok := answers[h]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	})()

	if got, ok := Resolve("10.0.0.5"); got != "10.0.0.5" || !ok || calls.Load() != 0 {
		t.Errorf("une IP est rendue telle quelle, sans requête : %q %v %d", got, ok, calls.Load())
	}
	if got, ok := Resolve("vm-docker"); got != "192.168.10.91" || !ok {
		t.Errorf("le nom se résout, l'IPv4 est préférée : %q %v", got, ok)
	}
	Resolve("vm-docker")
	if calls.Load() != 1 {
		t.Errorf("le résultat est gardé : %d requêtes", calls.Load())
	}
	if got, ok := Resolve("inconnu"); got != "inconnu" || ok {
		t.Errorf("un nom qui ne se résout pas reste tel quel : %q %v", got, ok)
	}
	if !FirstFailure("inconnu") || FirstFailure("inconnu") {
		t.Error("l'échec n'est signalé qu'une fois")
	}
	if FirstFailure("vm-docker") {
		t.Error("un nom résolu n'est pas un échec")
	}

	// Une résolution qui échoue après un succès garde l'adresse connue.
	mu.Lock()
	cache["vm-docker"].at = cache["vm-docker"].at.AddDate(0, 0, -1)
	mu.Unlock()
	fail = true
	if got, ok := Resolve("vm-docker"); got != "192.168.10.91" || !ok {
		t.Errorf("l'adresse connue est gardée : %q %v", got, ok)
	}
}
