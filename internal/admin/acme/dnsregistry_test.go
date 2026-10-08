// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"reflect"
	"strings"
	"testing"
)

// Caractérisation des fournisseurs DNS. Ce fichier a précédé la migration vers le registre de
// modules : NewProvider et ProviderConfigFromEnv doivent rendre exactement ce que rendaient les
// anciens switch.

func TestNewProvider_BuildsEveryType(t *testing.T) {
	cases := []struct {
		typ    string
		params map[string]string
		want   DNSProvider
	}{
		{"ovh", map[string]string{"app_key": "k", "app_secret": "s", "consumer_key": "c", "zone": "example.com"},
			&ovhProvider{endpoint: "https://eu.api.ovh.com/1.0", appKey: "k", appSecret: "s", consumerKey: "c", zone: "example.com"}},
		{"ovh", map[string]string{"endpoint": "https://ca.api.ovh.com/1.0", "zone": "z"},
			&ovhProvider{endpoint: "https://ca.api.ovh.com/1.0", zone: "z"}},
		{"cloudflare", map[string]string{"api_token": "tok", "zone_id": "z1"}, &cloudflareProvider{token: "tok", zoneID: "z1"}},
		{"cloudflare", map[string]string{"CF_API_TOKEN": "alias"}, &cloudflareProvider{token: "alias"}},
		{"route53", map[string]string{"hosted_zone_id": "Z123", "access_key_id": "AK", "secret_access_key": "SK", "session_token": "ST"},
			&route53Provider{hostedZoneID: "Z123", accessKey: "AK", secretKey: "SK", sessionToken: "ST"}},
		{"hetzner", map[string]string{"api_token": "t", "zone_id": "z"}, &hetznerProvider{apiToken: "t", zoneID: "z"}},
		{"gandi", map[string]string{"api_key": "k"}, &gandiProvider{apiKey: "k"}},
	}
	for _, c := range cases {
		got, err := NewProvider(ProviderConfig{Type: c.typ, Params: c.params})
		if err != nil {
			t.Errorf("%s %v : %v", c.typ, c.params, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s : got %#v, want %#v", c.typ, got, c.want)
		}
	}
}

func TestNewProvider_RefusesMissingRequiredParams(t *testing.T) {
	for typ, params := range map[string]map[string]string{
		"cloudflare": {},
		"route53":    {},
		"hetzner":    {"api_token": "t"},
		"gandi":      {},
	} {
		if _, err := NewProvider(ProviderConfig{Type: typ, Params: params}); err == nil {
			t.Errorf("%s %v : config incomplète acceptée", typ, params)
		}
	}
}

func TestNewProvider_UnknownType(t *testing.T) {
	_, err := NewProvider(ProviderConfig{Type: "carrier-pigeon"})
	if err == nil || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("err = %v", err)
	}
}

func TestProviderConfigFromEnv_EveryType(t *testing.T) {
	env := map[string]string{
		"OVH_ENDPOINT": "e", "OVH_APPLICATION_KEY": "ak", "OVH_APPLICATION_SECRET": "as", "OVH_CONSUMER_KEY": "ck", "OVH_ZONE": "oz",
		"CF_API_TOKEN": "cft", "CF_ZONE_ID": "cfz", "GANDI_API_KEY": "gk", "AWS_HOSTED_ZONE_ID": "hz",
		"AWS_ACCESS_KEY_ID": "ak", "AWS_SECRET_ACCESS_KEY": "sk", "AWS_SESSION_TOKEN": "st",
		"HETZNER_API_KEY": "ht", "HETZNER_ZONE_ID": "hzid",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	want := map[string]map[string]string{
		"ovh":        {"endpoint": "e", "app_key": "ak", "app_secret": "as", "consumer_key": "ck", "zone": "oz"},
		"cloudflare": {"api_token": "cft", "zone_id": "cfz"},
		"gandi":      {"api_key": "gk"},
		"route53":    {"hosted_zone_id": "hz", "access_key_id": "ak", "secret_access_key": "sk", "session_token": "st"},
		"hetzner":    {"api_token": "ht", "zone_id": "hzid"},
	}
	for typ, params := range want {
		got := ProviderConfigFromEnv(typ)
		if got.Type != typ || !reflect.DeepEqual(got.Params, params) {
			t.Errorf("%s : got %+v, want %v", typ, got, params)
		}
	}
	// Un type inconnu donne une config vide, jamais d'erreur ni de nil.
	if got := ProviderConfigFromEnv("inconnu"); got.Type != "inconnu" || got.Params == nil || len(got.Params) != 0 {
		t.Errorf("inconnu : %+v", got)
	}
}

// Les clés absentes de l'environnement restent présentes, vides : mergeProviderParams en dépend.
func TestProviderConfigFromEnv_KeepsEmptyKeys(t *testing.T) {
	for _, k := range []string{"CF_API_TOKEN", "CF_ZONE_ID"} {
		t.Setenv(k, "")
	}
	got := ProviderConfigFromEnv("cloudflare")
	if v, ok := got.Params["api_token"]; !ok || v != "" {
		t.Errorf("api_token = %q, présent=%v", v, ok)
	}
	if v, ok := got.Params["zone_id"]; !ok || v != "" {
		t.Errorf("zone_id = %q, présent=%v", v, ok)
	}
}
