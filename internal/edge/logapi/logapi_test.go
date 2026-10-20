// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logapi

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParamsSurviveAnEncodeDecodeRoundTrip(t *testing.T) {
	in := Params{
		Level: "warn", Component: "edge", Domain: "a.example.com", IP: "203.0.113.4", Method: "GET", Status: "4xx",
		Path: "/x", TLSJA3: "abc", TLSJA4: "t13", Search: "scan", DateFrom: "2026-10-21T10:00:00Z",
		DateTo: "2026-10-21T11:00:00Z", Kind: "access", ExcludeInternal: true, Cursor: "c", Limit: 50, Bulk: true,
		TZOffsetMin: 120, Bucket: "hour", Fields: "level,domain",
	}
	if got := ParamsFromValues(in.Values()); got != in {
		t.Fatalf("aller-retour différent :\n got %+v\nwant %+v", got, in)
	}
	if v := (Params{}).Values(); len(v) != 0 {
		t.Fatalf("des paramètres vides doivent donner une requête vide : %v", v)
	}
	if ParamsFromValues(url.Values{"exclude_internal": {"true"}}).ExcludeInternal != true {
		t.Fatal("exclude_internal=true non reconnu")
	}
}

func TestCursorRoundTripAndValidation(t *testing.T) {
	pos := map[string]Pos{"access": {"2026-10-21T10:00:00.000000Z", 42}, "system": {"2026-10-21T09:00:00.000000Z", 7}}
	got, err := DecodeCursor(EncodeCursor(pos))
	if err != nil || len(got) != 2 || got["access"] != pos["access"] || got["system"] != pos["system"] {
		t.Fatalf("aller-retour = %v, %v", got, err)
	}
	if c := EncodeCursor(map[string]Pos{"access": {}}); c != "" {
		t.Fatalf("une position vide ne doit pas produire de jeton : %q", c)
	}
	if m, err := DecodeCursor(""); err != nil || m != nil {
		t.Fatalf("jeton vide = %v, %v", m, err)
	}
	for name, c := range map[string]string{
		"pas du base64": "!!!", "trop long": strings.Repeat("a", MaxCursorBytes+1),
		"type inconnu": "eyJhdXRyZSI6eyJ0cyI6IngiLCJpZCI6MX19",
	} {
		if _, err := DecodeCursor(c); err == nil {
			t.Errorf("%s : jeton accepté", name)
		}
	}
}

// Le curseur reprend l'horodatage d'une Entry tel quel : il doit être à largeur fixe et valide en RFC3339.
func TestTsLayoutIsFixedWidthAndRFC3339(t *testing.T) {
	a := time.Date(2026, 10, 21, 10, 0, 0, 100000000, time.UTC).Format(TsLayout)
	b := time.Date(2026, 10, 21, 10, 0, 0, 120000000, time.UTC).Format(TsLayout)
	if len(a) != len(b) || !(a < b) {
		t.Fatalf("%q et %q : largeur variable ou ordre texte faux", a, b)
	}
	if _, err := time.Parse(time.RFC3339Nano, a); err != nil {
		t.Fatalf("%q n'est pas du RFC3339 : %v", a, err)
	}
}
