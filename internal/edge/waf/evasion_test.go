// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

// Une charge encodée dans le chemin, doublement encodée, placée dans le nom d'un paramètre ou envoyée sous un type
// de contenu que le WAF ne décode pas est lue par de nombreux backends : les règles doivent aussi la voir.
func TestInspect_EncodedPayloadsAreSeen(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	for _, tc := range []struct{ name, method, target, ct, body string }{
		{"traversée avec slash encodé", "GET", "/files/..%2f..%2fetc/passwd", "", ""},
		{"xss encodé dans le chemin", "GET", "/%3Cscript%3Ealert(1)%3C/script%3E", "", ""},
		{"sqli doublement encodé", "GET", "/x?q=1%2520UNION%2520SELECT%2520password%2520FROM%2520users", "", ""},
		{"sqli encodé dans le nom du paramètre", "GET", "/x?1%20UNION%20SELECT%20password%20FROM%20users=1", "", ""},
		{"formulaire sous text/plain", "POST", "/x", "text/plain", "q=1%20UNION%20SELECT%20password%20FROM%20users"},
	} {
		r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		if tc.ct != "" {
			r.Header.Set("Content-Type", tc.ct)
		}
		if len(e.Inspect(r, 1)) == 0 {
			t.Errorf("%s : aucune règle", tc.name)
		}
	}
}

// Décoder davantage ne doit pas transformer le trafic ordinaire en alertes.
func TestInspect_EncodedBenignTrafficStaysClean(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	for _, tc := range []struct{ name, method, target, ct, body string }{
		{"recherche", "GET", "/search?q=hello+world&page=2", "", ""},
		{"pourcentage encodé", "GET", "/p/100%25-coton?couleur=bleu%20marine", "", ""},
		{"fichier avec espace", "GET", "/img/photo%20vacances.png", "", ""},
		{"accents", "GET", "/recherche?q=caf%C3%A9+cr%C3%A8me", "", ""},
		{"json ordinaire", "POST", "/api/items", "application/json", `{"name":"Table basse","price":120,"tags":["bois","salon"]}`},
		{"formulaire ordinaire", "POST", "/login", "application/x-www-form-urlencoded", "user=alice%40exemple.fr&remember=on"},
	} {
		r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		if tc.ct != "" {
			r.Header.Set("Content-Type", tc.ct)
		}
		if m := e.Inspect(r, 1); len(m) != 0 {
			t.Errorf("%s : faux positif %+v", tc.name, m)
		}
	}
}

func TestDecodedVariants(t *testing.T) {
	if got := decodedVariants("a%2520b", 100); len(got) != 2 || got[0] != "a%20b" || got[1] != "a b" {
		t.Errorf("double décodage = %q", got)
	}
	if decodedVariants("rien-a-decoder", 100) != nil {
		t.Error("une valeur sans %% ni + n'a pas de variante")
	}
	if decodedVariants("a%20b", 3) != nil {
		t.Error("une valeur au-delà du plafond n'est pas recopiée")
	}
	if decodedVariants("%zz", 100) != nil {
		t.Error("un encodage invalide ne produit pas de variante")
	}
}
