// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Le choix du fournisseur au renouvellement se lit dans l'erreur : chaque fournisseur refuse une
// configuration vide avec son propre message, avant tout appel réseau à l'AC.

func newRenewManager(t *testing.T) *Manager {
	t.Helper()
	// Aucun identifiant ne doit venir de l'environnement de la machine de test.
	for _, k := range []string{"CF_API_TOKEN", "CF_ZONE_ID", "GANDI_API_KEY", "HETZNER_API_KEY", "HETZNER_ZONE_ID",
		"OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY", "OVH_ZONE", "OVH_ENDPOINT",
		"AWS_HOSTED_ZONE_ID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
	db, err := admindb.Open(filepath.Join(t.TempDir(), "acme.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	m := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, "ops@example.com")
	m.Providers = NewProviderStore(filepath.Join(t.TempDir(), "providers.yaml"))
	return m
}

func (m *Manager) testInsertCert(t *testing.T, domain, providerID string) {
	t.Helper()
	if _, err := m.db.Exec(`INSERT INTO certs (id, domain, issuer, expires_at, acme_provider_id)
		VALUES (?, ?, 'letsencrypt', '2026-12-01 00:00:00', ?)`, "c-"+domain, domain, providerID); err != nil {
		t.Fatal(err)
	}
}

func (m *Manager) testInsertDomain(t *testing.T, domain, dnsProvider, creds string) {
	t.Helper()
	if _, err := m.db.Exec(`INSERT INTO domains (id, domain, dns_provider, dns_credentials, cert_method)
		VALUES (?, ?, ?, ?, 'dns')`, "d-"+domain, domain, dnsProvider, creds); err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("err = %v, attendu un message contenant %q", err, substr)
	}
}

func TestRenew_UsesTheNamedProviderRememberedOnTheCert(t *testing.T) {
	m := newRenewManager(t)
	id, err := m.Providers.Create("mon-hetzner", "hetzner", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	m.testInsertCert(t, "example.com", id)
	m.testInsertDomain(t, "example.com", "gandi", "{}") // doit être ignoré : le fournisseur nommé gagne
	wantErr(t, m.renewCert(t.Context(), "example.com"), "hetzner")
}

func TestRenew_FallsBackToDomainWhenNamedProviderWasDeleted(t *testing.T) {
	m := newRenewManager(t)
	m.testInsertCert(t, "example.com", "supprime")
	m.testInsertDomain(t, "example.com", "gandi", "{}")
	wantErr(t, m.renewCert(t.Context(), "example.com"), "gandi")
}

// Avant correction, le renouvellement d'un domaine DNS-01 utilisait toujours le fournisseur par
// défaut (nul sans variable d'environnement : panique), jamais celui du domaine.
func TestRenew_UsesTheDomainProviderAndCredentials(t *testing.T) {
	m := newRenewManager(t)
	m.testInsertCert(t, "example.com", "")
	m.testInsertDomain(t, "example.com", "cloudflare", "{}")
	wantErr(t, m.renewCert(t.Context(), "example.com"), "cloudflare")
}

func TestRenew_NoProviderAtAllIsAnErrorNotAPanic(t *testing.T) {
	m := newRenewManager(t)
	m.testInsertCert(t, "example.com", "")
	wantErr(t, m.renewCert(t.Context(), "example.com"), "aucun fournisseur DNS")
}

func TestObtainWithNamedProvider_Errors(t *testing.T) {
	m := newRenewManager(t)
	wantErr(t, m.ObtainCertWithNamedProvider(t.Context(), "example.com", "inconnu"), "introuvable")
	m.Providers = nil
	wantErr(t, m.ObtainCertWithNamedProvider(t.Context(), "example.com", "x"), "aucun fournisseur DNS nommé")
	if m.NamedProviderExists("x") {
		t.Fatal("sans magasin, aucun fournisseur nommé n'existe")
	}
}

func TestNamedProviderExists(t *testing.T) {
	m := newRenewManager(t)
	id, _ := m.Providers.Create("g", "gandi", map[string]string{"api_key": "k"})
	if !m.NamedProviderExists(id) || m.NamedProviderExists("autre") || m.NamedProviderExists("") {
		t.Fatal("NamedProviderExists incohérent")
	}
}

func TestSetCertProvider_RememberAndClear(t *testing.T) {
	m := newRenewManager(t)
	m.testInsertCert(t, "example.com", "")
	read := func() string {
		var id string
		_ = m.db.QueryRow(`SELECT acme_provider_id FROM certs WHERE domain='example.com'`).Scan(&id)
		return id
	}
	m.setCertProvider(t.Context(), "example.com", "abc")
	if read() != "abc" {
		t.Fatal("identifiant non mémorisé")
	}
	m.setCertProvider(t.Context(), "example.com", "")
	if read() != "" {
		t.Fatal("identifiant non effacé")
	}
}
