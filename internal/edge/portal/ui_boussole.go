// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import _ "embed"

// boussoleIndexHTML est l'interface du thème « boussole » : même API, mêmes jetons de session et mêmes placeholders
// (__PORTAL_VIEW__, __PORTAL_TITLE__, __PORTAL_TAGLINE__) que portalIndexHTML. Elle vit dans un fichier à part pour garder un
// HTML lisible, JavaScript compris.
//
//go:embed ui_boussole.html
var boussoleIndexHTML string
