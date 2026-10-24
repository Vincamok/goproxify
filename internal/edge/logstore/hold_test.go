// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fileExists(s *Store, name string) bool {
	_, err := os.Stat(filepath.Join(s.opts.Dir, name))
	return err == nil
}

func TestLegalHoldBlocksThePurgeUntilReleased(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	s.Add(KindAccess, access(at("2026-10-07T08:00:00Z"), "198.51.100.1")) // semaine du 2026-10-05, expirée
	s.Add(KindAccess, access(at("2026-09-01T08:00:00Z"), "198.51.100.2")) // semaine du 2026-08-31, expirée, hors gel
	s.Add(KindSystem, Entry{Ts: at("2026-10-08T08:00:00Z"), Level: "info", Message: "système expiré"})
	s.Flush()

	h, err := s.AddHold(Hold{Reason: "réquisition 2026/1234", From: at("2026-10-06T00:00:00Z"), To: at("2026-10-09T00:00:00Z"), By: "opérateur"})
	if err != nil || h.ID == "" || h.CreatedAt.IsZero() {
		t.Fatalf("AddHold = %+v, %v", h, err)
	}
	s.Purge(now)
	if !fileExists(s, "access-2026-10-05.db") || !fileExists(s, "system-2026-10.db") {
		t.Fatal("un fichier gelé a été purgé")
	}
	if fileExists(s, "access-2026-08-31.db") {
		t.Error("un fichier expiré hors du gel doit être purgé")
	}
	if rows, _ := s.ReadAfter(KindAccess, 0, 10); len(rows) != 1 || rows[0].IP != "198.51.100.1" {
		t.Fatalf("lignes gelées = %+v", rows)
	}

	// Le gel est lu dans le registre à chaque purge : une autre instance le lève.
	other := openTest(t, func(o *Options) { o.Dir = s.opts.Dir; o.ReadOnly = true })
	if holds, err := other.Holds(); err != nil || len(holds) != 1 || holds[0].Reason != "réquisition 2026/1234" {
		t.Fatalf("registre vu d'une autre instance = %+v, %v", holds, err)
	}
	if err := other.RemoveHold(h.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveHold(h.ID); err != ErrHoldNotFound {
		t.Errorf("lever deux fois : %v", err)
	}
	s.Purge(now)
	if fileExists(s, "access-2026-10-05.db") || fileExists(s, "system-2026-10.db") {
		t.Fatal("la rétention doit reprendre une fois le gel levé")
	}
}

func TestUnreadableHoldRegistryPurgesNothing(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	s.Add(KindAccess, access(at("2026-10-07T08:00:00Z"), "198.51.100.1"))
	s.Flush()
	if err := os.WriteFile(s.holdsPath(), []byte("{pas du json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Purge(now)
	if !fileExists(s, "access-2026-10-05.db") {
		t.Fatal("un registre illisible a valu « aucun gel » : des données ont été purgées")
	}
}

func TestHoldNeedsAReasonAndAValidRange(t *testing.T) {
	s := openTest(t)
	from := at("2026-10-01T00:00:00Z")
	for name, h := range map[string]Hold{
		"sans motif":     {From: from, To: from.Add(time.Hour)},
		"plage inversée": {Reason: "x", From: from, To: from.Add(-time.Hour)},
		"sans dates":     {Reason: "x"},
	} {
		if _, err := s.AddHold(h); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestScanFiltersByRangeDomainAndIPAndRevealsPseudonymizedIPs(t *testing.T) {
	k := key(t)
	s := openTest(t, func(o *Options) { o.IPKey = k })
	const real = "203.0.113.42"
	add := func(ts, domain, ip, realIP string) {
		e := access(at(ts), ip)
		e.Domain, e.RealIP, e.IPTruncated = domain, realIP, realIP != ""
		s.Add(KindAccess, e)
	}
	add("2026-10-19T10:00:00Z", "a.example", "198.51.100.1", "")  // avant la plage
	add("2026-10-20T10:00:00Z", "a.example", "203.0.113.0", real) // pseudonymisée
	add("2026-10-20T11:00:00Z", "b.example", "198.51.100.9", "")  // autre domaine, autre IP
	add("2026-10-27T10:00:00Z", "a.example", "198.51.100.1", "")  // semaine suivante, dans la plage
	add("2026-11-30T10:00:00Z", "a.example", "198.51.100.1", "")  // après la plage
	s.Add(KindSystem, Entry{Ts: at("2026-10-21T08:00:00Z"), Level: "warn", Message: "système"})
	s.Flush()

	collect := func(kind Kind, f ScanFilter) (out []Row) {
		if err := s.Scan(kind, f, func(r Row) error { out = append(out, r); return nil }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rng := ScanFilter{From: at("2026-10-20T00:00:00Z"), To: at("2026-10-31T00:00:00Z")}
	if rows := collect(KindAccess, rng); len(rows) != 3 || rows[0].RealIP != real || rows[1].Domain != "b.example" {
		t.Fatalf("plage seule = %+v", rows)
	}
	f := rng
	f.Domain = "a.example"
	if rows := collect(KindAccess, f); len(rows) != 2 {
		t.Fatalf("domaine = %d lignes", len(rows))
	}
	// L'IP réelle retrouve la ligne pseudonymisée (empreinte) ; la même IP en clair d'une autre ligne aussi.
	f = rng
	f.IP = real
	if rows := collect(KindAccess, f); len(rows) != 1 || rows[0].IP != "203.0.113.0" || rows[0].RealIP != real {
		t.Fatalf("IP pseudonymisée = %+v", rows)
	}
	f.IP = "198.51.100.1"
	if rows := collect(KindAccess, f); len(rows) != 1 || rows[0].Ts.Day() != 27 {
		t.Fatalf("IP en clair = %+v", rows)
	}
	f.IP = "pas une ip"
	if err := s.Scan(KindAccess, f, func(Row) error { return nil }); err != ErrBadIP {
		t.Fatalf("IP invalide : %v", err)
	}
	if rows := collect(KindSystem, ScanFilter{From: at("2026-10-01T00:00:00Z"), To: at("2026-10-31T00:00:00Z")}); len(rows) != 1 || rows[0].Message != "système" {
		t.Fatalf("système = %+v", rows)
	}
}

func TestReadOnlyStoreReadsWithoutWritingOrPurging(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	s.Add(KindAccess, access(at("2026-10-07T08:00:00Z"), "198.51.100.1"))
	s.Flush()

	// La rétention par défaut (365 jours) purgerait ce fichier : une ouverture en lecture seule n'y touche pas.
	ro, err := Open(Options{Dir: s.opts.Dir, ReadOnly: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if ro.Add(KindAccess, access(now, "198.51.100.2")) {
		t.Error("Add doit être refusé en lecture seule")
	}
	n := 0
	if err := ro.Scan(KindAccess, ScanFilter{From: at("2026-10-01T00:00:00Z"), To: at("2026-10-31T00:00:00Z")}, func(Row) error { n++; return nil }); err != nil || n != 1 {
		t.Fatalf("Scan = %d, %v", n, err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	if !fileExists(s, "access-2026-10-05.db") {
		t.Fatal("la lecture seule a purgé un fichier")
	}
}

func scanAll(t *testing.T, s *Store, kind Kind, f ScanFilter) []Row {
	t.Helper()
	var out []Row
	if err := s.Scan(kind, f, func(r Row) error { out = append(out, r); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// Un gel visant une IP garde ses lignes (pseudonymisées comprises) au-delà de la rétention, et seulement elles : le
// fichier de période est supprimé avec les lignes des autres.
func TestFilteredHoldKeepsOnlyTheTargetedRowsPastTheRetention(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	k := key(t)
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now }; o.IPKey = k })
	const real = "203.0.113.42"
	target := access(at("2026-10-07T08:00:00Z"), "203.0.113.0")
	target.RealIP, target.IPTruncated, target.Path = real, true, "/cible-pseudo"
	s.Add(KindAccess, target)
	s.Add(KindAccess, access(at("2026-10-08T08:00:00Z"), "198.51.100.2")) // autre personne, même fichier
	clear := access(at("2026-10-09T08:00:00Z"), real)
	clear.Path = "/cible-clair"
	s.Add(KindAccess, clear)
	out := access(at("2026-09-02T08:00:00Z"), real) // la même IP, mais hors de la plage du gel
	out.Path = "/hors-plage"
	s.Add(KindAccess, out)
	s.Flush()

	h, err := s.AddHold(Hold{Reason: "réquisition 2026/1234", IP: " " + real + " ", From: at("2026-10-06T00:00:00Z"), To: at("2026-10-31T00:00:00Z")})
	if err != nil || h.IP != real {
		t.Fatalf("AddHold = %+v, %v", h, err)
	}
	// Une ligne qui arrive après la pose du gel est gardée à la purge.
	later := access(at("2026-10-10T08:00:00Z"), real)
	later.Path = "/cible-tardive"
	s.Add(KindAccess, later)
	s.Flush()

	s.Purge(now)
	if fileExists(s, "access-2026-10-05.db") || fileExists(s, "access-2026-08-31.db") {
		t.Fatal("un gel filtré ne doit pas garder les fichiers entiers")
	}
	if rows, _ := s.ReadAfter(KindAccess, 0, 100); len(rows) != 0 {
		t.Fatalf("lignes restantes dans la base : %d", len(rows))
	}
	rows := scanAll(t, s, KindAccess, ScanFilter{From: at("2026-01-01T00:00:00Z"), To: at("2027-01-01T00:00:00Z")})
	var paths []string
	for _, r := range rows {
		paths = append(paths, r.Path)
	}
	if strings.Join(paths, ",") != "/cible-pseudo,/cible-clair,/cible-tardive" {
		t.Fatalf("lignes gardées = %v", paths)
	}
	if rows[0].RealIP != real || rows[0].IP != "203.0.113.0" || !rows[0].Pseudonymized {
		t.Errorf("la ligne pseudonymisée perd son IP réelle : %+v", rows[0])
	}
	// Le filtre de l'export s'applique aussi aux archives.
	if got := scanAll(t, s, KindAccess, ScanFilter{From: at("2026-10-08T00:00:00Z"), To: at("2026-10-09T23:00:00Z")}); len(got) != 1 || got[0].Path != "/cible-clair" {
		t.Fatalf("export borné = %+v", got)
	}

	// Un ordre d'effacement explicite vaut aussi pour l'archive ; lever le gel la supprime.
	if n, err := s.EraseIP(real); err != nil || n != 3 {
		t.Fatalf("EraseIP = %d, %v", n, err)
	}
	if got := scanAll(t, s, KindAccess, ScanFilter{From: at("2026-01-01T00:00:00Z"), To: at("2027-01-01T00:00:00Z")}); len(got) != 0 {
		t.Fatalf("lignes encore lisibles après l'effacement : %d", len(got))
	}
	if err := s.RemoveHold(h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.heldPath(h.ID)); !os.IsNotExist(err) {
		t.Error("l'archive du gel levé subsiste")
	}
}

func TestFilteredHoldByDomainAndTheBoundaryFileReadsEachRowOnce(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	mk := func(ts, domain, path string) Entry {
		e := access(at(ts), "198.51.100.5")
		e.Domain, e.Path = domain, path
		return e
	}
	// Semaine du 2026-10-19, à cheval sur la limite de rétention (2026-10-21T12:00).
	s.Add(KindAccess, mk("2026-10-20T08:00:00Z", "gel.example", "/vieille"))
	s.Add(KindAccess, mk("2026-10-20T09:00:00Z", "autre.example", "/vieille-autre"))
	s.Add(KindAccess, mk("2026-10-22T08:00:00Z", "gel.example", "/recente"))
	s.Flush()
	h, err := s.AddHold(Hold{Reason: "procédure", Domain: "gel.example", From: at("2026-10-19T00:00:00Z"), To: at("2026-10-26T00:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	s.Purge(now)
	rows, _ := s.ReadAfter(KindAccess, 0, 100)
	if len(rows) != 1 || rows[0].Path != "/recente" {
		t.Fatalf("la base garde %+v, attendu la ligne récente seule", rows)
	}
	got := scanAll(t, s, KindAccess, ScanFilter{From: at("2026-10-19T00:00:00Z"), To: at("2026-10-26T00:00:00Z")})
	var paths []string
	for _, r := range got {
		paths = append(paths, r.Path)
	}
	if strings.Join(paths, ",") != "/vieille,/recente" {
		t.Fatalf("export = %v (une ligne gardée est lue une fois, celle d'un autre domaine a disparu)", paths)
	}
	_ = h
}

func TestFilteredHoldRejectsABadIP(t *testing.T) {
	s := openTest(t)
	_, err := s.AddHold(Hold{Reason: "x", IP: "pas une ip", From: at("2026-10-01T00:00:00Z"), To: at("2026-10-02T00:00:00Z")})
	if err != ErrBadIP {
		t.Fatalf("IP invalide : %v", err)
	}
	if holds, _ := s.Holds(); len(holds) != 0 {
		t.Error("un gel invalide a été enregistré")
	}
}

// Un identifiant n'est jamais réattribué : effacer les dernières lignes ne fait pas reculer LastID, et la ligne suivante
// reçoit un numéro plus grand que celles qu'un consommateur a déjà vues.
func TestLastIDNeverGoesBackAfterAnErasureAndSkipsEmptyFiles(t *testing.T) {
	s := openTest(t)
	s.Add(KindAccess, access(at("2026-10-05T08:00:00Z"), "198.51.100.1"))
	s.Add(KindAccess, access(at("2026-10-21T08:00:00Z"), "203.0.113.9"))
	s.Flush()
	before := s.LastID(KindAccess)
	if before == 0 {
		t.Fatal("LastID vaut 0 avec des lignes")
	}
	if n, err := s.EraseIP("203.0.113.9"); err != nil || n != 1 {
		t.Fatalf("EraseIP = %d, %v", n, err)
	}
	if got := s.LastID(KindAccess); got != before {
		t.Fatalf("LastID a reculé après l'effacement : %d → %d", before, got)
	}
	s.Add(KindAccess, access(at("2026-10-22T08:00:00Z"), "198.51.100.2"))
	s.Flush()
	if got := s.LastID(KindAccess); got <= before {
		t.Fatalf("l'identifiant suivant n'est pas plus grand : %d après %d", got, before)
	}
	if s.LastID(KindSystem) != 0 {
		t.Error("LastID d'un type sans ligne doit valoir 0")
	}
}

// Un fichier créé avant l'AUTOINCREMENT n'a pas de ligne dans sqlite_sequence : sa fin reste la dernière ligne écrite,
// sans quoi la passerelle prend sa base pour remplacée et renvoie tout à chaque tour.
func TestLastIDOfAFileCreatedBeforeAutoincrementIsItsLastRow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "system-2026-10.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(strings.Replace(schema, "AUTOINCREMENT", "", 1)); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		s.Add(KindSystem, Entry{Ts: at("2026-10-21T08:00:00Z"), Level: "warn", Component: "edge", Message: "x"})
	}
	s.Flush()
	rows, err := s.ReadAfter(KindSystem, 0, 10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("ReadAfter = %d lignes, %v", len(rows), err)
	}
	if got := s.LastID(KindSystem); got != rows[2].ID {
		t.Fatalf("LastID = %d, la dernière ligne est %d", got, rows[2].ID)
	}
}

// SetRetention change la durée que la purge suivante applique ; une durée nulle est ignorée.
func TestSetRetentionIsUsedByTheNextPurge(t *testing.T) {
	now := at("2026-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return now } })
	s.Add(KindAccess, access(at("2026-08-03T08:00:00Z"), "198.51.100.1")) // 80 jours : gardée à 365 jours, purgée à 30
	s.Flush()
	s.Purge(now)
	if !fileExists(s, "access-2026-08-03.db") {
		t.Fatal("la rétention par défaut (365 jours) a purgé un fichier de 80 jours")
	}
	s.SetRetention(KindAccess, 0)
	if s.Retention(KindAccess) != 365*24*time.Hour {
		t.Fatal("une durée nulle a été appliquée")
	}
	s.SetRetention(KindAccess, 30*24*time.Hour)
	s.Purge(now)
	if fileExists(s, "access-2026-08-03.db") {
		t.Fatal("la nouvelle rétention (30 jours) n'a pas purgé le fichier")
	}
}
