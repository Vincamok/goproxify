// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import "time"

// blockLogWindow : une ligne de journal par IP, par motif et par minute pour les refus répétés.
const blockLogWindow = time.Minute

// blockedAttrs ajoute le nombre de refus regroupés à une ligne de journal, quand il y en a.
func blockedAttrs(suppressed int, attrs ...any) []any {
	if suppressed > 0 {
		attrs = append(attrs, "repeats", suppressed)
	}
	return attrs
}
