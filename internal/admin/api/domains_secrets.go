// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/modules"
)

// Les identifiants DNS d'un domaine (jetons d'API, clés) sont lisibles par tout rôle qui peut lire le domaine :
// ils sont masqués en sortie, et une modification qui omet un secret ou renvoie le masque conserve la valeur
// enregistrée. Le manifeste du fournisseur dit quels champs sont secrets ; pour un fournisseur sans manifeste,
// tout champ dont le nom évoque un secret l'est.

var secretNameFragments = []string{"secret", "token", "password", "passwd", "key", "credential"}

func dnsCredManifest(provider string, creds ...map[string]any) modules.Manifest {
	if man, ok := acme.DNSProviderManifest(provider); ok {
		return man
	}
	man := modules.Manifest{Type: provider}
	seen := map[string]bool{}
	for _, c := range creds {
		for k, v := range c {
			if _, isStr := v.(string); !isStr || seen[k] {
				continue
			}
			lk := strings.ToLower(k)
			for _, f := range secretNameFragments {
				if strings.Contains(lk, f) {
					seen[k] = true
					man.Fields = append(man.Fields, modules.Field{Key: k, Kind: modules.KindPassword, Secret: true})
					break
				}
			}
		}
	}
	return man
}

func asCredMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func maskDNSCreds(provider string, creds any) any {
	m := asCredMap(creds)
	if m == nil {
		return creds
	}
	return dnsCredManifest(provider, m).Mask(m)
}

// keepDNSCreds complète les identifiants reçus avec ceux de l'enregistrement quand le fournisseur est inchangé ;
// des identifiants absents conservent ceux enregistrés. Un masque sans valeur d'origine est écarté.
func keepDNSCreds(oldProvider, newProvider, oldJSON string, next any) any {
	var old map[string]any
	_ = json.Unmarshal([]byte(oldJSON), &old)
	if oldProvider != newProvider {
		old = nil
	}
	if next == nil {
		if len(old) == 0 {
			return nil
		}
		return old
	}
	nm := asCredMap(next)
	if nm == nil {
		return next
	}
	return dnsCredManifest(newProvider, nm, old).KeepSecrets(old, nm)
}
