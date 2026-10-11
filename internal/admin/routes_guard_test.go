// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Une route enregistrée avec protected(…) seul est ouverte à tout compte authentifié, quel que soit son rôle : le
// contrôle de rôle, s'il existe, est dans le handler. Cette liste est celle des routes relues une à une ; ajouter une
// route à protected(…) sans l'inscrire ici fait échouer le test, ce qui force à se demander si un compte « user »
// doit pouvoir l'appeler. (declared-nodes et bootstrap-tickets y étaient, sans contrôle : un compte sans privilège
// pouvait déclarer des nœuds et créer des tickets d'enrôlement.)
var openToAnyAuthenticatedAccount = map[string]string{
	"/api/v1/proxies":                    "droits par domaine dans le handler",
	"/api/v1/proxies/":                   "droits par domaine dans le handler",
	"/api/v1/nodes":                      "écritures réservées aux admins dans le handler",
	"/api/v1/nodes/":                     "écritures réservées aux admins dans le handler",
	"GET /api/v1/architecture/groups":    "lecture seule",
	"/api/v1/node-events":                "lecture seule",
	"/api/v1/discovered-containers":      "lecture seule",
	"/api/v1/backends/health":            "lecture seule",
	"/api/v1/metrics/proxies":            "lecture seule",
	"/api/v1/metrics/summary":            "lecture seule",
	"/api/v1/audit":                      "filtré selon le rôle dans le handler",
	"/api/v1/audit/":                     "filtré selon le rôle dans le handler",
	"/api/v1/alert-channel-types":        "lecture seule",
	"/api/v1/logs/reveal-ip":             "droit gdpr:reveal vérifié dans le handler",
	"GET /api/v1/edges/waf-status":       "lecture seule",
	"/api/v1/prism/":                     "lecture ; réglage SLO réservé aux admins dans le handler",
	"/api/v1/me":                         "compte de l'appelant",
	"/api/v1/me/":                        "compte de l'appelant",
	"/api/v1/me/tokens":                  "jetons de l'appelant, scopes bornés par son rôle",
	"/api/v1/me/tokens/":                 "jetons de l'appelant, scopes bornés par son rôle",
	"GET /api/v1/auth/me":                "compte de l'appelant",
	"/api/v1/auth/mfa":                   "second facteur de l'appelant",
	"/api/v1/auth/mfa/":                  "second facteur de l'appelant",
}

func TestRoutesOpenToAnyAccountAreReviewed(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\("([^"]+)",\s*protected\(`)
	found := map[string]bool{}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, ":=") {
			continue
		}
		if m := re.FindStringSubmatch(line); m != nil {
			found[m[1]] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("aucune route trouvée : le motif ne correspond plus à server.go")
	}
	var unreviewed []string
	for route := range found {
		if _, ok := openToAnyAuthenticatedAccount[route]; !ok {
			unreviewed = append(unreviewed, route)
		}
	}
	sort.Strings(unreviewed)
	if len(unreviewed) > 0 {
		t.Fatalf("routes ouvertes à tout compte authentifié sans revue : %v — utiliser adminOnly/adminWrites/operatorWrites, ou les inscrire dans openToAnyAuthenticatedAccount avec la raison", unreviewed)
	}
	for route := range openToAnyAuthenticatedAccount {
		if !found[route] {
			t.Errorf("%q est dans la liste mais n'est plus enregistrée avec protected(…) : la retirer", route)
		}
	}
}
