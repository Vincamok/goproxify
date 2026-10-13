// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

type fakeLibdns struct {
	mu      sync.Mutex
	zone    string
	records []libdns.RR
	failAdd error
	deletes [][]libdns.Record
}

func (f *fakeLibdns) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdd != nil {
		return nil, f.failAdd
	}
	f.zone = zone
	for _, r := range recs {
		f.records = append(f.records, r.RR())
	}
	return recs, nil
}

func (f *fakeLibdns) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, recs)
	var kept []libdns.RR
	for _, have := range f.records {
		match := false
		for _, want := range recs {
			w := want.RR()
			if w.Name == have.Name && (w.Type == "" || w.Type == have.Type) && (w.Data == "" || w.Data == have.Data) {
				match = true
			}
		}
		if !match {
			kept = append(kept, have)
		}
	}
	f.records = kept
	return nil, nil
}

func fakeProvider(zone string, api *fakeLibdns) *libdnsProvider {
	return &libdnsProvider{typ: "fake", api: api, zone: zone, ttl: libdnsTXTTTL, set: map[string][]string{}}
}

func TestLibdns_ChallengeNamesAreRelativeToTheZone(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct{ zone, domain, wantZone, wantName string }{
		"apex déduit":            {"", "example.com", "example.com.", "_acme-challenge"},
		"sous-domaine déduit":    {"", "app.example.com", "example.com.", "_acme-challenge.app"},
		"joker":                  {"", "*.example.com", "example.com.", "_acme-challenge"},
		"suffixe à deux parties": {"", "app.example.co.uk", "example.co.uk.", "_acme-challenge.app"},
		"zone déléguée":          {"sub.example.com", "api.sub.example.com", "sub.example.com.", "_acme-challenge.api"},
	} {
		api := &fakeLibdns{}
		if err := fakeProvider(tc.zone, api).SetTXTRecord(ctx, tc.domain, "tok"); err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		if api.zone != tc.wantZone || len(api.records) != 1 || api.records[0].Name != tc.wantName || api.records[0].Data != "tok" || api.records[0].Type != "TXT" {
			t.Errorf("%s : zone=%q records=%+v", name, api.zone, api.records)
		}
	}
	if err := fakeProvider("example.com", &fakeLibdns{}).SetTXTRecord(ctx, "autre.org", "x"); err == nil {
		t.Error("un domaine hors de la zone doit être refusé")
	}
}

func TestLibdns_DeleteOnlyRemovesWhatItSet(t *testing.T) {
	ctx := context.Background()
	api := &fakeLibdns{records: []libdns.RR{{Name: "_acme-challenge", Type: "TXT", Data: "etranger"}}}
	p := fakeProvider("", api)
	// Un joker et son apex posent deux valeurs sous le même nom.
	for _, v := range []string{"a", "b"} {
		if err := p.SetTXTRecord(ctx, "example.com", v); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(api.records) != 1 || api.records[0].Data != "etranger" {
		t.Fatalf("seules les valeurs posées par l'instance partent : %+v", api.records)
	}
	// Sans rien de posé (nettoyage avant une commande), tout TXT du nom de challenge est retiré.
	if err := fakeProvider("", api).DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(api.records) != 0 {
		t.Fatalf("nettoyage : %+v", api.records)
	}
}

func TestLibdns_ErrorsCarryTheProvider(t *testing.T) {
	api := &fakeLibdns{failAdd: errors.New("401 jeton refusé")}
	err := fakeProvider("", api).SetTXTRecord(context.Background(), "example.com", "x")
	if err == nil || !strings.Contains(err.Error(), "fake") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}

func TestLibdns_FactoryFillsTheProviderFromParams(t *testing.T) {
	p, err := NewProvider(ProviderConfig{Type: "digitalocean", Params: map[string]string{"auth_token": "  tok  ", "zone": "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	lp := p.(*libdnsProvider)
	if lp.zone != "example.com" {
		t.Errorf("zone = %q", lp.zone)
	}
	if _, err := NewProvider(ProviderConfig{Type: "digitalocean", Params: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "auth_token") {
		t.Errorf("champ requis absent : %v", err)
	}
	if _, err := NewProvider(ProviderConfig{Type: "godaddy", Params: map[string]string{"api_token": "k:s"}}); err != nil {
		t.Error(err)
	}
	if got := p.(*libdnsProvider).ttl; got != libdnsTXTTTL {
		t.Errorf("ttl = %v", got)
	}
	g, _ := NewProvider(ProviderConfig{Type: "godaddy", Params: map[string]string{"api_token": "k:s"}})
	if g.(*libdnsProvider).ttl < 600*1e9 {
		t.Errorf("GoDaddy exige au moins 600 s : %v", g.(*libdnsProvider).ttl)
	}
}

// Toutes les clés de manifeste doivent exister dans la structure du fournisseur (étiquette JSON) : sinon un champ saisi
// serait ignoré sans erreur.
func TestLibdns_EveryManifestKeyReachesTheProvider(t *testing.T) {
	for _, s := range libdnsSpecs {
		params := map[string]string{}
		for _, p := range s.fields {
			params[p.key] = "valeur-" + p.key
		}
		// Le décodage JSON ignore une clé inconnue : on le vérifie en relisant la structure reconstruite.
		prov, err := newLibdnsFactory(s)(params)
		if err != nil {
			t.Errorf("%s : %v", s.typ, err)
			continue
		}
		dump := dumpJSON(t, prov.(*libdnsProvider).api)
		for _, p := range s.fields {
			if !strings.Contains(dump, "valeur-"+p.key) {
				t.Errorf("%s : le paramètre %q n'atteint pas la configuration du fournisseur", s.typ, p.key)
			}
		}
	}
}

func TestLibdns_APIURLsAreChecked(t *testing.T) {
	for name, tc := range map[string]struct {
		typ string
		url string
		ok  bool
	}{
		"https public":              {"linode", "https://api.linode.com/v4", true},
		"http refusé":               {"linode", "http://api.linode.com/v4", false},
		"adresse interne refusée":   {"linode", "https://10.0.0.5/", false},
		"métadonnées refusées":      {"dnsimple", "https://169.254.169.254/", false},
		"vide accepté":              {"linode", "", true},
		"auto-hébergé en http":      {"powerdns", "http://10.0.0.5:8081", true},
		"auto-hébergé : métadonnée": {"powerdns", "http://169.254.169.254/", false},
	} {
		key := "api_url"
		if tc.typ == "powerdns" {
			key = "server_url"
		}
		err := ValidateDNSParams(tc.typ, map[string]any{key: tc.url})
		if (err == nil) != tc.ok {
			t.Errorf("%s : err = %v", name, err)
		}
	}
}

func dumpJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
