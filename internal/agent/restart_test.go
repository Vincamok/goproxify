package agent

import (
	"testing"
	"time"
)

func TestRequestRestart_StopsTheAgentAndFlagsTheRelaunch(t *testing.T) {
	restartRequested.Store(false)
	done := make(chan struct{})
	old := terminateSelf
	terminateSelf = func() { close(done) }
	defer func() { terminateSelf = old; restartRequested.Store(false) }()

	if RestartRequested() {
		t.Fatal("aucune relance demandée au départ")
	}
	requestRestart()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("l'arrêt propre n'a pas été demandé")
	}
	if !RestartRequested() {
		t.Error("la relance doit être demandée")
	}
}
