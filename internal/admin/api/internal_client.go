// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"time"

	"github.com/vincamok/goproxify/internal/ssrf"
)

// internalClient joint les passerelles et agents à l'endpoint qu'ils ont eux-mêmes déclaré à l'appairage. Une
// passerelle compromise ne doit pas pouvoir faire appeler par l'Admin, avec son jeton, les métadonnées du cloud :
// le link-local est refusé à la connexion (le réseau privé reste joignable, c'est là que vivent les passerelles).
var internalClient = ssrf.SelfHostedClient(2 * time.Minute)
