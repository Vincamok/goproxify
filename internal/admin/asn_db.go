// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
)

// asnDBPath retourne l'emplacement de la base des systèmes autonomes : GPX_ASN_DB_PATH, sinon
// <stockage>/asn/ip2asn-combined.tsv.gz. Sans stockage, un dossier temporaire : la base se
// retélécharge alors à chaque redémarrage de l'Admin.
func asnDBPath(basePath string) string {
	if p := os.Getenv("GPX_ASN_DB_PATH"); p != "" {
		return p
	}
	if basePath == "" {
		return filepath.Join(os.TempDir(), "goproxify-ip2asn.tsv.gz")
	}
	return filepath.Join(basePath, "asn", "ip2asn-combined.tsv.gz")
}
