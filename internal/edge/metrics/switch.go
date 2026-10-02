// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "sync/atomic"

var requestOff atomic.Bool

// SetRequestMetricsDisabled coupe l'enregistrement des métriques par requête (benchmark) ; /metrics reste servi.
func SetRequestMetricsDisabled(off bool) { requestOff.Store(off) }

// RequestMetricsOn indique si les métriques par requête sont enregistrées.
func RequestMetricsOn() bool { return !requestOff.Load() }
