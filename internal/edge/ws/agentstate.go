// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// AgentStateFiles : fichiers d'état locaux d'un Agent, copiés chez sa passerelle pour être
// sauvegardés avec elle et rendus à un Agent dont le volume a disparu.
var AgentStateFiles = []string{"agent.token", "agent.hmac", "agent-node-id", "agent-edges.json"}

const maxAgentStateFileBytes = 64 << 10

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func agentStateDir() string {
	dir := os.Getenv("GPX_EDGE_DATA_DIR")
	if dir == "" {
		dir = "/etc/goproxify"
	}
	return filepath.Join(dir, "agent-states")
}

func agentStatePath(agentID string) string {
	return filepath.Join(agentStateDir(), strings.TrimLeft(unsafeID.ReplaceAllString(agentID, "_"), ".")+".json")
}

func allowedStateFile(name string) bool {
	for _, n := range AgentStateFiles {
		if n == name {
			return true
		}
	}
	return false
}

// saveAgentState conserve l'état annoncé par un Agent approuvé (nom de fichier et taille filtrés).
func (h *Hub) saveAgentState(agentID string, payload json.RawMessage) {
	var p AgentStatePayload
	if json.Unmarshal(payload, &p) != nil || len(p.Files) == 0 {
		return
	}
	clean := AgentStatePayload{Files: map[string][]byte{}}
	for name, data := range p.Files {
		if allowedStateFile(name) && len(data) <= maxAgentStateFileBytes {
			clean.Files[name] = data
		}
	}
	if len(clean.Files) == 0 {
		return
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return
	}
	if err := os.MkdirAll(agentStateDir(), 0o700); err != nil {
		return
	}
	dst := agentStatePath(agentID)
	tmp := dst + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		if os.Rename(tmp, dst) != nil {
			os.Remove(tmp)
		}
	}
}

// restoreAgentState renvoie à un Agent revenu sans état local ce que sa passerelle a conservé.
func (h *Hub) restoreAgentState(ac *agentConn) {
	raw, err := os.ReadFile(agentStatePath(ac.id))
	if err != nil {
		return
	}
	var p AgentStatePayload
	if json.Unmarshal(raw, &p) != nil || len(p.Files) == 0 {
		return
	}
	// Le HMAC courant fait foi : celui du magasin de la passerelle, jamais une copie périmée.
	if strings.TrimSpace(ac.hmac) != "" {
		p.Files["agent.hmac"] = []byte(ac.hmac)
	}
	msg, err := NewMessage(ac.seq.Add(1), TypeRestoreState, p)
	if err != nil {
		return
	}
	if h.sendToAgent(ac, msg) == nil {
		h.log.Info("ws/agent: état local restitué à l'Agent", "agent", ac.id, "files", len(p.Files))
	}
}
