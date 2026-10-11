// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/ssrf"
)

// selfHostedClient est le client HTTP des canaux auto-hébergés (voir ssrf.SelfHostedClient).
func selfHostedClient(timeout time.Duration) *http.Client { return ssrf.SelfHostedClient(timeout) }
