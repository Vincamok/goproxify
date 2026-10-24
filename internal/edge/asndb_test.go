// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/asncompact"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func asnTestData(t *testing.T) ([]byte, string) {
	t.Helper()
	var ranges []asncompact.Range
	for i := 0; i < 400; i++ {
		ranges = append(ranges, asncompact.Range{
			Start: netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}),
			End:   netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 255}),
			ASN:   uint32(64500 + i),
		})
	}
	data, version, err := asncompact.Encode(ranges)
	if err != nil {
		t.Fatal(err)
	}
	return data, version
}

func chunks(data []byte, version string, n int) []edgews.ASNChunkPayload {
	size := (len(data) + n - 1) / n
	var out []edgews.ASNChunkPayload
	for i := 0; i < n; i++ {
		end := (i + 1) * size
		if end > len(data) {
			end = len(data)
		}
		out = append(out, edgews.ASNChunkPayload{Version: version, Seq: i, Total: n, Data: data[i*size : end]})
	}
	return out
}

func TestASNDatabaseIsAssembledPersistedAndReloadedWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_ASN_DB_PATH", filepath.Join(dir, "asn-db.gpx"))
	s := newEphorGateway(t, dir)
	data, version := asnTestData(t)

	if s.lookupASN("10.0.5.7") != 0 {
		t.Fatal("sans base, aucune IP n'a d'ASN")
	}
	parts := chunks(data, version, 3)
	for _, i := range []int{2, 0, 1} { // arrivée dans le désordre
		s.applyASNChunk(parts[i])
		if i != 1 && s.asnVersion() != "" {
			t.Fatal("la base ne s'installe qu'une fois tous les morceaux reçus")
		}
	}
	if s.asnVersion() != version {
		t.Fatalf("version installée %q, attendue %q", s.asnVersion(), version)
	}
	if got := s.lookupASN("10.0.5.7"); got != 64505 {
		t.Fatalf("10.0.5.7 → AS%d", got)
	}
	if s.lookupASN("not an ip") != 0 || s.lookupASN("192.0.2.1") != 0 {
		t.Fatal("adresse illisible ou inconnue : 0")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "asn-db.gpx"))
	if err != nil {
		t.Fatalf("la base doit être copiée sur le volume : %v", err)
	}
	if strings.Contains(string(raw), "GPXASN") {
		t.Fatal("la copie locale doit être chiffrée")
	}

	restarted := newEphorGateway(t, dir)
	restarted.loadASNFromDisk()
	if got := restarted.lookupASN("10.1.0.9"); got != 64756 {
		t.Fatalf("après redémarrage sans l'Admin : 10.1.0.9 → AS%d", got)
	}
}

func TestASNChunksOfAnotherVersionOrBrokenAreIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_ASN_DB_PATH", filepath.Join(dir, "asn-db.gpx"))
	s := newEphorGateway(t, dir)
	data, version := asnTestData(t)

	// Annoncée d'une version, livrée d'une autre : refusée.
	for _, c := range chunks(data, "deadbeef0000", 2) {
		s.applyASNChunk(c)
	}
	if s.asnVersion() != "" {
		t.Fatal("une base dont l'empreinte n'est pas celle annoncée ne s'installe pas")
	}
	// Données illisibles.
	s.applyASNChunk(edgews.ASNChunkPayload{Version: "aaaaaaaaaaaa", Seq: 0, Total: 1, Data: []byte("pas une base")})
	// Paramètres absurdes.
	s.applyASNChunk(edgews.ASNChunkPayload{Version: version, Seq: 5, Total: 2, Data: data})
	s.applyASNChunk(edgews.ASNChunkPayload{Version: version, Seq: 0, Total: 100000, Data: data})
	s.applyASNChunk(edgews.ASNChunkPayload{})
	if s.asnVersion() != "" {
		t.Fatalf("rien ne devait s'installer : %q", s.asnVersion())
	}

	// Un bon envoi après les mauvais s'installe, et le nouveau remplace l'ancien.
	for _, c := range chunks(data, version, 2) {
		s.applyASNChunk(c)
	}
	if s.asnVersion() != version {
		t.Fatal("la base valide doit s'installer")
	}
}

func TestASNOfferForTheVersionWeHaveAsksForNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_ASN_DB_PATH", filepath.Join(dir, "asn-db.gpx"))
	s := newEphorGateway(t, dir)
	data, version := asnTestData(t)
	for _, c := range chunks(data, version, 1) {
		s.applyASNChunk(c)
	}
	// Ni panique ni demande : le hub n'a aucun Admin connecté, on vérifie seulement que les deux cas passent.
	s.handleASNOffer(edgews.ASNOfferPayload{Version: version})
	s.handleASNOffer(edgews.ASNOfferPayload{Version: "autre-version"})
	s.handleASNOffer(edgews.ASNOfferPayload{})
}
