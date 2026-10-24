// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func geoTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	for _, s := range []string{
		`CREATE TABLE logs (ts DATETIME, domain TEXT DEFAULT '', node_name TEXT DEFAULT '', ip TEXT DEFAULT '', path TEXT DEFAULT '', status INTEGER DEFAULT 0)`,
		`CREATE TABLE geoip_cache (ip TEXT PRIMARY KEY, country_code TEXT, country_name TEXT, lat REAL, lon REAL, city TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE security_bans (ip TEXT, expires_at DATETIME)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestGetGeoPoints(t *testing.T) {
	db := geoTestDB(t)
	// Le trafic de chaque IP, additionné sur les passerelles (voir GeoPointsFromIPs).
	counts := []IPCount{{IP: "1.1.1.1", Requests: 4, Errors: 1}, {IP: "2.2.2.2", Requests: 2}, {IP: "3.3.3.3", Requests: 5}, {IP: "4.4.4.4", Requests: 4}, {IP: "5.5.5.5", Requests: 9}}
	db.Exec(`INSERT INTO geoip_cache VALUES ('1.1.1.1','FR','France',48.85,2.35,'Paris','IDF')`)
	db.Exec(`INSERT INTO geoip_cache VALUES ('2.2.2.2','FR','France',48.86,2.34,'Paris','IDF')`)
	db.Exec(`INSERT INTO geoip_cache VALUES ('3.3.3.3','DE','Germany',52.52,13.4,'Berlin','BE')`)
	db.Exec(`INSERT INTO geoip_cache VALUES ('4.4.4.4','XX','Unknown',0,0,'','')`) // position inconnue
	db.Exec(`INSERT INTO security_bans VALUES ('2.2.2.2', NULL)`)

	pts := GeoPointsFromIPs(context.Background(), db, counts, 0) // 5.5.5.5 n'est pas dans le cache : ignorée
	if len(pts) != 2 {
		t.Fatalf("2 villes attendues (IP non localisée exclue), got %d: %+v", len(pts), pts)
	}
	// Paris : 4+2 requêtes, 1 erreur, 2 IPs dont 1 bannie ; Berlin : 5 requêtes.
	var paris, berlin GeoPoint
	for _, p := range pts {
		switch p.City {
		case "Paris":
			paris = p
		case "Berlin":
			berlin = p
		}
	}
	if paris.Requests != 6 || paris.Errors != 1 || paris.IPs != 2 || paris.BannedIPs != 1 {
		t.Errorf("Paris inattendu : %+v", paris)
	}
	if berlin.Requests != 5 || berlin.CountryCode != "DE" {
		t.Errorf("Berlin inattendu : %+v", berlin)
	}
	if pts[0].City != "Paris" {
		t.Errorf("tri par volume décroissant attendu, got %s en premier", pts[0].City)
	}
}
