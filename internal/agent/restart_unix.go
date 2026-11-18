// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package agent

import (
	"os"
	"syscall"
)

// Reexec remplace le processus par une nouvelle instance du même binaire, avec les mêmes arguments : même PID (donc le
// conteneur ne s'arrête pas), configuration relue. Ne revient qu'en cas d'échec.
func Reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
