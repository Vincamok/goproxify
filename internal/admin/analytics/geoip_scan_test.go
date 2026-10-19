package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestResolveAdvancesScanWatermark(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ts := time.Now().UTC().Format(time.RFC3339)
	insert := func(ip string) int64 {
		res, err := d.Exec(`INSERT INTO logs (ts, domain, ip, status) VALUES (?,?,?,?)`, ts, "a.fr", ip, 200)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	last := insert("10.1.2.3")

	g := &GeoResolver{DB: d}
	g.resolve(context.Background())
	if g.scannedID != last {
		t.Fatalf("scannedID = %d, attendu %d : la plage épuisée doit être marquée", g.scannedID, last)
	}

	// Une IP déjà passée sous la borne n'est plus relue ; la nouvelle l'est.
	d.Exec(`DELETE FROM geoip_cache`)
	last = insert("10.9.9.9")
	g.resolve(context.Background())
	var n int
	d.QueryRow(`SELECT count(*) FROM geoip_cache`).Scan(&n)
	if n != 1 {
		t.Fatalf("cache = %d entrées, attendu 1 (seule la ligne postérieure à la borne)", n)
	}
	if g.scannedID != last {
		t.Fatalf("scannedID = %d, attendu %d", g.scannedID, last)
	}

	// Une IP publique que rien ne peut résoudre ne doit pas faire avancer la borne : réessai au prochain tour.
	pub := insert("203.0.113.77")
	g.resolve(context.Background())
	if g.scannedID >= pub {
		t.Fatalf("scannedID = %d : l'IP non résolue serait perdue", g.scannedID)
	}
}
