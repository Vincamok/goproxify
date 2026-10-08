// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package acme gère l'obtention et le renouvellement des certificats Let's Encrypt
// pour l'Administration via ACME DNS-01 (wildcards).
// Les clés privées ne sont jamais écrites en base — elles sont poussées en RAM vers les passerelles.
package acme

import "context"

// DNSProvider sait écrire et supprimer un enregistrement TXT DNS.
type DNSProvider interface {
	SetTXTRecord(ctx context.Context, domain, value string) error
	DeleteTXTRecord(ctx context.Context, domain string) error
}

// ProviderConfig contient les paramètres d'un fournisseur DNS.
type ProviderConfig struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}
