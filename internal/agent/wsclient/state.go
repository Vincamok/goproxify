// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package wsclient

import (
	"os"
	"path/filepath"
	"strings"

	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// stateDir : volume de l'Agent (modifiable pour les tests).
var stateDir = "/etc/goproxify"

// stateIsFresh : ni token d'appairage ni HMAC sur le volume — l'Agent a perdu son état (volume
// supprimé ou nouveau). Sa passerelle, si elle en a gardé une copie, la lui rend.
func stateIsFresh() bool {
	for _, name := range []string{"agent.token", "agent.hmac"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err == nil {
			return false
		}
	}
	return true
}

// readState lit les fichiers d'état présents.
func readState() map[string][]byte {
	out := map[string][]byte{}
	for _, name := range edgeWS.AgentStateFiles {
		if data, err := os.ReadFile(filepath.Join(stateDir, name)); err == nil && len(data) > 0 {
			out[name] = data
		}
	}
	return out
}

// applyRestoredState écrit l'état reçu de la passerelle et renvoie le HMAC restauré, s'il y en a un.
func applyRestoredState(files map[string][]byte) string {
	allowed := map[string]bool{}
	for _, n := range edgeWS.AgentStateFiles {
		allowed[n] = true
	}
	_ = os.MkdirAll(stateDir, 0o755)
	hmac := ""
	for name, data := range files {
		if !allowed[name] {
			continue
		}
		if os.WriteFile(filepath.Join(stateDir, name), data, 0o600) != nil {
			continue
		}
		if name == "agent.hmac" {
			hmac = strings.TrimSpace(string(data))
		}
	}
	return hmac
}

// pushState copie l'état local chez la passerelle pour qu'il soit sauvegardé avec elle.
func (c *Client) pushState() {
	if files := readState(); len(files) > 0 {
		c.sendJSON(edgeWS.TypeAgentState, edgeWS.AgentStatePayload{Files: files})
	}
}
