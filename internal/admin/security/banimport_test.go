// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"strings"
	"testing"
)

func vals(es []ImportEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Value
	}
	return out
}

// Listes publiques : commentaires # et ;, lignes vides, fins de ligne Windows, BOM.
func TestParseImportTextPublicLists(t *testing.T) {
	content := string(rune(0xFEFF)) + "# FireHOL level1\r\n; Spamhaus DROP\r\n\r\n" +
		"1.10.16.0/20 ; SBL256894\r\n" +
		"203.0.113.5\r\n" +
		"198.51.100.0/24   # scanner\r\n" +
		"2001:db8::/32;SBL1\r\n" +
		"203.0.113.9 note ignorée sans marqueur\r\n"
	es, format, err := ParseImport(content, "")
	if err != nil || format != ImportFormatText {
		t.Fatalf("%v %s", err, format)
	}
	want := []string{"1.10.16.0/20", "203.0.113.5", "198.51.100.0/24", "2001:db8::/32", "203.0.113.9"}
	if got := vals(es); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("valeurs : %v", got)
	}
	if es[0].Reason != "SBL256894" || es[2].Reason != "scanner" || es[3].Reason != "SBL1" || es[1].Reason != "" || es[4].Reason != "" {
		t.Fatalf("motifs : %+v", es)
	}
	if es[0].Line != 4 || es[4].Line != 8 {
		t.Fatalf("numéros de ligne : %d %d", es[0].Line, es[4].Line)
	}
}

// Le CSV de l'export des bans se réimporte tel quel : les colonnes inconnues sont ignorées.
func TestParseImportCSVExportRoundTrip(t *testing.T) {
	content := "id,ip,domain,reason,source,edge_name,expires_at,created_at\n" +
		"b1,203.0.113.5,,scan,fail2ban,paris,2026-12-31T23:59:59Z,2026-01-01T00:00:00Z\n" +
		"b2,198.51.100.0/24,app.test,\"abus, répété\",native,,,2026-01-02T00:00:00Z\n"
	es, format, err := ParseImport(content, "")
	if err != nil || format != ImportFormatCSV || len(es) != 2 {
		t.Fatalf("%v %s %+v", err, format, es)
	}
	if es[0].Value != "203.0.113.5" || es[0].Reason != "scan" || es[0].ExpiresAt != "2026-12-31T23:59:59Z" {
		t.Fatalf("ligne 1 : %+v", es[0])
	}
	if es[1].Value != "198.51.100.0/24" || es[1].Domain != "app.test" || es[1].Reason != "abus, répété" || es[1].ExpiresAt != "" {
		t.Fatalf("ligne 2 : %+v", es[1])
	}
	if es[0].Line != 2 {
		t.Fatalf("la ligne 2 du fichier est la première donnée : %d", es[0].Line)
	}
}

func TestParseImportCSVWithoutHeader(t *testing.T) {
	es, _, err := ParseImport("203.0.113.5,scanner\n198.51.100.0/24,bot\n", ImportFormatCSV)
	if err != nil || len(es) != 2 || es[0].Value != "203.0.113.5" || es[0].Reason != "scanner" || es[1].Line != 2 {
		t.Fatalf("%v %+v", err, es)
	}
	es, _, _ = ParseImport("address,comment\n203.0.113.5,x\n", "")
	if len(es) != 1 || es[0].Value != "203.0.113.5" {
		t.Fatalf("colonne address : %+v", es)
	}
}

func TestParseImportJSON(t *testing.T) {
	es, format, err := ParseImport(`["203.0.113.5", "198.51.100.0/24"]`, "")
	if err != nil || format != ImportFormatJSON || strings.Join(vals(es), "|") != "203.0.113.5|198.51.100.0/24" {
		t.Fatalf("chaînes : %v %s %+v", err, format, es)
	}
	es, _, err = ParseImport(`[{"ip":"203.0.113.5","reason":"scan","domain":"a.test","expires_at":"2026-12-31T23:59:59Z","source":"x"},{"cidr":"198.51.100.0/24"}]`, "")
	if err != nil || len(es) != 2 || es[0].Reason != "scan" || es[0].Domain != "a.test" || es[0].ExpiresAt == "" || es[1].Value != "198.51.100.0/24" {
		t.Fatalf("objets : %v %+v", err, es)
	}
	if _, _, err := ParseImport(`[{"ip":`, ""); err == nil {
		t.Fatal("JSON tronqué")
	}
	if _, _, err := ParseImport(`[1, 2]`, ""); err == nil {
		t.Fatal("nombres : chaîne ou objet attendu")
	}
}

func TestParseImportErrors(t *testing.T) {
	cases := map[string]string{
		"":                   "vide",
		"   \n\n":            "vide",
		"# que des notes\n;": "aucune entrée",
	}
	for in, want := range cases {
		if _, _, err := ParseImport(in, ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q : %v, attendu %q", in, err, want)
		}
	}
	if _, _, err := ParseImport("1.2.3.4", "xml"); err == nil {
		t.Error("format inconnu")
	}
	big := strings.Repeat("203.0.113.5\n", MaxImportEntries+1)
	if _, _, err := ParseImport(big, ""); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Errorf("trop d'entrées : %v", err)
	}
	if _, _, err := ParseImport(strings.Repeat("a", MaxImportBytes+1), ""); err == nil {
		t.Error("trop volumineux")
	}
}

// La validation d'une valeur est faite plus tard : une valeur invalide reste dans la liste lue.
func TestParseImportKeepsInvalidValues(t *testing.T) {
	es, _, err := ParseImport("pas-une-ip\n203.0.113.5\n", "")
	if err != nil || len(es) != 2 || es[0].Value != "pas-une-ip" {
		t.Fatalf("%v %+v", err, es)
	}
}
