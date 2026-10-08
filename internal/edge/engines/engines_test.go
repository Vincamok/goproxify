// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package engines

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestManifestsOrderAndSentinelPaths(t *testing.T) {
	var types []string
	for _, m := range Manifests() {
		types = append(types, m.Type)
	}
	if strings.Join(types, ",") != "sentinel,fail2ban,crowdsec" {
		t.Fatalf("types = %v", types)
	}
	sm, _ := Manifest(Sentinel)
	have := map[string]bool{}
	for _, f := range sm.Fields {
		have[f.Key] = true
	}
	for _, k := range []string{"enabled", "mode", "ip_score.ban_threshold", "ip_score.errors.weights", "escalation.factor", "lists.ip_sources", "custom_lists.tls_fingerprints", "whitelist.paths", "tarpit.delay_ms", "ban_duration"} {
		if !have[k] {
			t.Errorf("champ %q absent du manifeste Sentinel", k)
		}
	}
}

// Une configuration que l'interface et les passerelles utilisent déjà doit rester valide.
func TestValidateAcceptsRealConfigs(t *testing.T) {
	ok := map[string]string{
		Sentinel: `{"enabled":true,"mode":"block","score_threshold":5,"global_rps":500,"rate_limit":20,"rate_window":"1s","error_threshold":30,"error_window":"10s","ban_duration":"24h",
			"ip_score":{"enabled":true,"ban_threshold":10,"half_life":"10m","errors":{"enabled":true,"weights":{"404":0.5,"405":2},"routes":[{"prefix":"/wp-admin","factor":3}]}},
			"escalation":{"enabled":true,"factor":2,"window":"168h","max_duration":"720h"},
			"lists":{"ua_enabled":true,"ip_sources":["https://example.com/list.txt"]},
			"custom_lists":{"ips":["203.0.113.0/24"],"uas":["badbot"],"paths":["/.env"],"tls_fingerprints":["e7d705a3286e19ea42f587b344ee6865"]},
			"whitelist":{"ips":["10.0.0.0/8"],"paths":["/health"]},"tarpit":{"enabled":true,"delay_ms":3000,"max_concurrent":100}}`,
		Fail2Ban: `{"enabled":true,"window_sec":300,"max_errors":50,"ban_duration_sec":0,"trust_forwarded_for":true,"whitelist":["10.0.0.0/8","203.0.113.7"]}`,
		CrowdSec: `{"enabled":true,"api_url":"http://localhost:8080","api_key":"k"}`,
	}
	for typ, body := range ok {
		if err := Validate(typ, json.RawMessage(body)); err != nil {
			t.Errorf("%s : %v", typ, err)
		}
	}
	for _, typ := range []string{Sentinel, Fail2Ban, CrowdSec} {
		if err := Validate(typ, nil); err != nil {
			t.Errorf("%s vide : %v", typ, err)
		}
	}
	if err := Validate(CrowdSec, json.RawMessage(`{"enabled":false}`)); err != nil {
		t.Errorf("crowdsec désactivé sans clé : %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	bad := map[string]struct{ typ, body string }{
		"sentinel clé inconnue":    {Sentinel, `{"enabled":true,"modee":"block"}`},
		"sentinel clé imbriquée":   {Sentinel, `{"ip_score":{"ban_treshold":3}}`},
		"sentinel mode":            {Sentinel, `{"mode":"off"}`},
		"sentinel durée illisible": {Sentinel, `{"ban_duration":"un jour"}`},
		"sentinel durée négative":  {Sentinel, `{"rate_window":"-5s"}`},
		"sentinel seuil négatif":   {Sentinel, `{"error_threshold":-1}`},
		"sentinel IP":              {Sentinel, `{"whitelist":{"ips":["10.0.0.0/99"]}}`},
		"sentinel code HTTP":       {Sentinel, `{"ip_score":{"errors":{"weights":{"abc":1}}}}`},
		"sentinel poids négatif":   {Sentinel, `{"ip_score":{"errors":{"weights":{"404":-1}}}}`},
		"sentinel préfixe route":   {Sentinel, `{"ip_score":{"errors":{"routes":[{"prefix":"admin","factor":1}]}}}`},
		"sentinel source":          {Sentinel, `{"lists":{"ip_sources":["ftp://x"]}}`},
		"sentinel chemin":          {Sentinel, `{"whitelist":{"paths":["health"]}}`},
		"sentinel tarpit":          {Sentinel, `{"tarpit":{"enabled":true,"delay_ms":90000}}`},
		"sentinel type":            {Sentinel, `{"global_rps":"vite"}`},
		"fail2ban clé":             {Fail2Ban, `{"window":300}`},
		"fail2ban négatif":         {Fail2Ban, `{"max_errors":-3}`},
		"fail2ban liste blanche":   {Fail2Ban, `{"whitelist":["nope"]}`},
		"crowdsec URL":             {CrowdSec, `{"api_url":"localhost:8080"}`},
		"crowdsec sans clé":        {CrowdSec, `{"enabled":true,"api_url":"http://localhost:8080"}`},
		"crowdsec clé inconnue":    {CrowdSec, `{"apikey":"k"}`},
	}
	for name, c := range bad {
		if err := Validate(c.typ, json.RawMessage(c.body)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if Validate("autre", nil) == nil {
		t.Error("moteur inconnu accepté")
	}
}

func TestCrowdSecKeyMaskedAndKept(t *testing.T) {
	masked := string(MaskConfig(CrowdSec, json.RawMessage(`{"enabled":true,"api_url":"http://l","api_key":"SECRET"}`)))
	if strings.Contains(masked, "SECRET") || !strings.Contains(masked, modules.Masque) || !strings.Contains(masked, "http://l") {
		t.Fatalf("masquage = %s", masked)
	}
	kept := string(KeepSecrets(CrowdSec, json.RawMessage(`{"api_key":"SECRET","api_url":"http://l"}`), json.RawMessage(`{"enabled":true,"api_url":"http://m","api_key":"`+modules.Masque+`"}`)))
	if !strings.Contains(kept, "SECRET") || !strings.Contains(kept, "http://m") || strings.Contains(kept, modules.Masque) {
		t.Fatalf("conservation = %s", kept)
	}
	omitted := string(KeepSecrets(CrowdSec, json.RawMessage(`{"api_key":"SECRET"}`), json.RawMessage(`{"enabled":false}`)))
	if !strings.Contains(omitted, "SECRET") {
		t.Fatalf("secret omis = %s", omitted)
	}
}
