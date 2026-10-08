// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"reflect"
	"testing"
)

var shippedDNSTypes = []string{"ovh", "cloudflare", "route53", "hetzner", "gandi"}

func TestDNSRegistry_ShippedTypesInOrder(t *testing.T) {
	var got []string
	for _, m := range DNSProviderManifests() {
		got = append(got, m.Type)
	}
	if !reflect.DeepEqual(got, shippedDNSTypes) {
		t.Fatalf("types = %v", got)
	}
}

// Tout jeton, clé ou secret doit être déclaré secret pour ne jamais sortir de l'API.
func TestDNSRegistry_CredentialsAreSecret(t *testing.T) {
	mustBeSecret := map[string][]string{
		"ovh": {"app_key", "app_secret", "consumer_key"}, "cloudflare": {"api_token"},
		"hetzner": {"api_token"}, "gandi": {"api_key"},
		"route53": {"access_key_id", "secret_access_key", "session_token"},
	}
	for typ, keys := range mustBeSecret {
		m, ok := DNSProviderManifest(typ)
		if !ok {
			t.Fatalf("%s absent", typ)
		}
		secrets := map[string]bool{}
		for _, f := range m.Fields {
			if f.Secret {
				secrets[f.Key] = true
			}
		}
		if len(secrets) != len(keys) {
			t.Errorf("%s : secrets = %v, attendu %v", typ, secrets, keys)
		}
		for _, k := range keys {
			if !secrets[k] {
				t.Errorf("%s.%s doit être secret", typ, k)
			}
		}
	}
}

// Les champs requis du manifeste doivent suffire à construire le fournisseur : si le formulaire
// les exige, NewProvider ne doit pas les refuser.
func TestDNSRegistry_RequiredFieldsAreEnoughToBuild(t *testing.T) {
	for _, m := range DNSProviderManifests() {
		params := map[string]string{}
		for _, f := range m.Fields {
			if f.Required {
				params[f.Key] = "x"
			}
		}
		if _, err := NewProvider(ProviderConfig{Type: m.Type, Params: params}); err != nil {
			t.Errorf("%s avec ses champs requis : %v", m.Type, err)
		}
	}
}

// Chaque paramètre déclare sa variable d'environnement : sans cela, un formulaire ou un
// générateur de configuration inventerait un nom de variable (c'était le cas de l'assistant
// de première installation).
func TestDNSRegistry_EnvVarsDeclared(t *testing.T) {
	for _, m := range DNSProviderManifests() {
		for _, f := range m.Fields {
			if f.Env == "" {
				t.Errorf("%s.%s sans variable d'environnement", m.Type, f.Key)
			}
		}
	}
}

// Aucun fournisseur ne doit plus se déclarer « non implémenté » : Route 53 l'a été, et le
// mécanisme ne sert qu'à signaler un module déclaré mais incapable d'émettre.
func TestDNSRegistry_NoProviderFlaggedNotImplemented(t *testing.T) {
	for _, m := range DNSProviderManifests() {
		if m.String("status") == DNSStatusNotImplemented {
			t.Errorf("%s est signalé non implémenté", m.Type)
		}
	}
}
