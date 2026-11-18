// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package agent

import "errors"

// Reexec n'est pas disponible hors Unix : l'Agent s'arrête et le superviseur (service, politique de redémarrage) le relance.
func Reexec() error { return errors.New("relance automatique non prise en charge sur cette plateforme") }
