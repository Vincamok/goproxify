package ws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAgentStateFiltersNamesSizeAndID(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	h := &Hub{}
	payload, _ := json.Marshal(AgentStatePayload{Files: map[string][]byte{
		"agent.hmac":       []byte("hm"),
		"agent.token":      []byte("tok"),
		"../evil":          []byte("x"),
		"authorized_keys":  []byte("x"),
		"agent-edges.json": []byte(strings.Repeat("a", maxAgentStateFileBytes+1)),
	}})
	h.saveAgentState("../../escape", payload)

	entries, _ := os.ReadDir(filepath.Join(root, "agent-states"))
	if len(entries) != 1 || strings.Contains(entries[0].Name(), "/") || strings.HasPrefix(entries[0].Name(), "..") {
		t.Fatalf("fichier d'état inattendu : %v", entries)
	}
	var got AgentStatePayload
	raw, _ := os.ReadFile(filepath.Join(root, "agent-states", entries[0].Name()))
	json.Unmarshal(raw, &got)
	if len(got.Files) != 2 || string(got.Files["agent.hmac"]) != "hm" {
		t.Fatalf("contenu filtré incorrect : %v", got.Files)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.json")); err == nil {
		t.Fatal("écriture hors du dossier d'états")
	}
}
