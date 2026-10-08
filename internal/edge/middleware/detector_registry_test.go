// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func detCfg(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDetectorTypes(t *testing.T) {
	got := DetectorTypes()
	want := []string{"bot", "geo_ip", "ip_filter", "waf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("types = %v", got)
	}
}

// Chaque clé JSON de la configuration d'exécution est déclarée dans le manifeste : une clé ajoutée à
// la structure sans manifeste serait refusée par l'API alors que le moteur la lirait.
func TestDetectorManifestsCoverRuntimeConfig(t *testing.T) {
	for typ, v := range map[string]any{
		"ip_filter": router.IPFilterConfig{}, "geo_ip": router.GeoIPConfig{},
		"bot": router.BotConfig{}, "waf": router.WAFConfig{},
	} {
		man, _ := DetectorManifest(typ)
		declared := map[string]bool{}
		for _, f := range man.Fields {
			declared[f.Key] = true
		}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			key := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			if key != "" && key != "-" && !declared[key] {
				t.Errorf("%s : clé %q absente du manifeste", typ, key)
			}
		}
	}
}

func TestValidateDetector(t *testing.T) {
	ok := map[string]string{
		"ip_filter": `{"mode":"allow","cidrs":["10.0.0.0/8","203.0.113.7","2001:db8::/32"]}`,
		"geo_ip":    `{"mode":"deny","countries":["cn","RU"]}`,
		"geo_ip2":   `{"mode":"deny","blocked_countries":["CN"],"db_path":"/x.mmdb"}`,
		"bot":       `{"enabled":true,"mode":"challenge","challenge_provider":"pow","challenge_difficulty":18,"challenge_ttl":"2h"}`,
		"bot2":      `{"enabled":true,"challenge_provider":"turnstile","challenge_site_key":"k","challenge_provider_secret":"s"}`,
		"waf":       `{"enabled":true,"mode":"detect","exclude_ids":[920350],"trusted_proxies":["10.0.0.0/8"],"custom_rules":[{"id":9001,"pattern":"(?i)evil","severity":"high","targets":["uri","args"],"message":"m"}]}`,
	}
	for name, body := range ok {
		typ := strings.TrimRight(name, "0123456789")
		if err := ValidateDetector(typ, detCfg(t, body)); err != nil {
			t.Errorf("%s : %v", name, err)
		}
	}
	bad := map[string]string{
		"ip_filter:mode":         `{"mode":"block","cidrs":["10.0.0.0/8"]}`,
		"ip_filter:cidr":         `{"mode":"deny","cidrs":["10.0.0.0/33"]}`,
		"ip_filter:vide":         `{"mode":"deny","cidrs":[]}`,
		"ip_filter:clé inconnue": `{"mode":"deny","cidrs":["10.0.0.1"],"cidr":["x"]}`,
		"geo_ip:pays":            `{"mode":"deny","countries":["FRA"]}`,
		"geo_ip:mode":            `{"mode":"","countries":["FR"]}`,
		"bot:mode":               `{"mode":"strict"}`,
		"bot:provider":           `{"challenge_provider":"recaptcha"}`,
		"bot:turnstile":          `{"challenge_provider":"turnstile"}`,
		"bot:difficulté":         `{"challenge_difficulty":40}`,
		"bot:ttl":                `{"challenge_ttl":"5s"}`,
		"waf:mode":               `{"mode":"off"}`,
		"waf:regex":              `{"custom_rules":[{"pattern":"("}]}`,
		"waf:cible":              `{"custom_rules":[{"pattern":"x","targets":["env"]}]}`,
		"waf:proxy":              `{"trusted_proxies":["not-a-net"]}`,
	}
	for name, body := range bad {
		typ := name[:strings.Index(name, ":")]
		if err := ValidateDetector(typ, detCfg(t, body)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if err := ValidateDetector("inconnu", map[string]any{}); err == nil {
		t.Error("type inconnu accepté")
	}
}

func TestDetectorSecretsAreMasked(t *testing.T) {
	man, _ := DetectorManifest("bot")
	out := man.Mask(detCfg(t, `{"challenge_secret":"S1","challenge_provider_secret":"S2","challenge_site_key":"public"}`))
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "S1") || strings.Contains(string(b), "S2") || !strings.Contains(string(b), "public") {
		t.Fatalf("masquage = %s", b)
	}
}
