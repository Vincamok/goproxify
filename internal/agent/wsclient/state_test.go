package wsclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAgentStateFreshnessReadAndRestore(t *testing.T) {
	stateDir = t.TempDir()
	if !stateIsFresh() {
		t.Fatal("volume vide non reconnu comme neuf")
	}
	hm := applyRestoredState(map[string][]byte{
		"agent.hmac":   []byte("secret-hmac\n"),
		"agent.token":  []byte("tok"),
		"../evil":      []byte("x"),
		"authorized_k": []byte("x"),
	})
	if hm != "secret-hmac" {
		t.Fatalf("HMAC restauré = %q", hm)
	}
	if stateIsFresh() {
		t.Fatal("volume restauré encore considéré comme neuf")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(stateDir), "evil")); err == nil {
		t.Fatal("écriture hors du volume")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "authorized_k")); err == nil {
		t.Fatal("fichier hors liste blanche écrit")
	}
	files := readState()
	if len(files) != 2 || string(files["agent.token"]) != "tok" {
		t.Fatalf("état relu : %v", files)
	}
}
