// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"sync/atomic"
	"syscall"
)

// restartRequested : l'arrêt en cours doit être suivi d'une relance de l'Agent par lui-même (nouvelle configuration
// appliquée), sans compter sur la politique de redémarrage du conteneur.
var restartRequested atomic.Bool

// terminateSelf déclenche l'arrêt propre du processus (le point d'entrée écoute SIGTERM). Remplaçable par les tests.
var terminateSelf = func() {
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Signal(syscall.SIGTERM)
	}
}

// requestRestart arrête l'Agent proprement et demande au point d'entrée de le relancer (Reexec).
func requestRestart() {
	restartRequested.Store(true)
	go terminateSelf()
}

// RestartRequested indique qu'un arrêt a été demandé pour appliquer une configuration : à la sortie du service, l'appelant
// appelle Reexec.
func RestartRequested() bool { return restartRequested.Load() }
