package edge

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupExportRestoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	os.MkdirAll(filepath.Join(root, "proxies"), 0o700)
	os.MkdirAll(filepath.Join(root, "geoip"), 0o700)
	os.WriteFile(filepath.Join(root, "proxies", "app.yaml"), []byte("host: app.fr"), 0o600)
	os.WriteFile(filepath.Join(root, "portal-config.gpx"), []byte("chiffré"), 0o600)
	os.WriteFile(filepath.Join(root, "geoip", "GeoLite2-City.mmdb"), []byte("gros"), 0o600)
	os.WriteFile(filepath.Join(root, "x.cast.gpx"), []byte("enregistrement"), 0o600)
	db, err := sql.Open("sqlite", filepath.Join(root, "bans.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE b (ip TEXT)`)
	db.Exec(`INSERT INTO b VALUES ('203.0.113.9')`)
	db.Close()

	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxies/app.yaml", "portal-config.gpx", "bans.db"} {
		if len(b.Files[want]) == 0 {
			t.Fatalf("%s absent de l'export : %v", want, keys(b.Files))
		}
	}
	for _, not := range []string{"geoip/GeoLite2-City.mmdb", "x.cast.gpx"} {
		if _, ok := b.Files[not]; ok {
			t.Fatalf("%s ne devrait pas être exporté", not)
		}
	}

	// Restauration sur un dossier vierge, avec une tentative d'évasion de chemin.
	root2 := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root2)
	b.Files["../evil.txt"] = []byte("x")
	b.Files["geoip/y.mmdb"] = []byte("x")
	body, _ := json.Marshal(b)
	rec = httptest.NewRecorder()
	s.handleBackupRestore(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/backup/restore", bytes.NewReader(body)))
	var res struct {
		Written  int      `json:"written"`
		Rejected []string `json:"rejected"`
	}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Written != 3 || len(res.Rejected) != 2 {
		t.Fatalf("résultat : %+v", res)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root2), "evil.txt")); err == nil {
		t.Fatal("écriture hors du dossier de données")
	}
	if data, _ := os.ReadFile(filepath.Join(root2, "proxies", "app.yaml")); string(data) != "host: app.fr" {
		t.Fatalf("proxy non restauré : %q", data)
	}
	db2, err := sql.Open("sqlite", filepath.Join(root2, "bans.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var ip string
	if err := db2.QueryRow(`SELECT ip FROM b`).Scan(&ip); err != nil || ip != "203.0.113.9" {
		t.Fatalf("base restaurée illisible : %q %v", ip, err)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBackupExportReportsSkippedWithReasonAndStreamsValidJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	t.Setenv("GPX_BACKUP_MAX_FILE_MB", "1")
	os.WriteFile(filepath.Join(root, "petit.gpx"), []byte("ok"), 0o600)
	os.WriteFile(filepath.Join(root, "gros.gpx"), bytes.Repeat([]byte("x"), 2<<20), 0o600)
	// Base WAL ouverte, comme en production : sa copie passe par un dossier de travail du volume.
	live, _ := sql.Open("sqlite", filepath.Join(root, "bans.db")+"?_pragma=journal_mode(WAL)")
	defer live.Close()
	live.SetMaxOpenConns(1)
	live.Exec(`CREATE TABLE b (ip TEXT)`)
	live.Exec(`INSERT INTO b VALUES ('203.0.113.9')`)

	rec := httptest.NewRecorder()
	(&Server{}).handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
	if string(b.Files["petit.gpx"]) != "ok" || len(b.Files["bans.db"]) == 0 {
		t.Fatalf("fichiers : %v", keys(b.Files))
	}
	if _, ok := b.Files["gros.gpx"]; ok {
		t.Fatal("fichier au-delà de la limite exporté")
	}
	if len(b.Skipped) != 1 || !strings.Contains(b.Skipped[0], "gros.gpx") || !strings.Contains(b.Skipped[0], "Mo par fichier") {
		t.Fatalf("raison absente : %v", b.Skipped)
	}
	if b.Sizes["petit.gpx"] != 2 || b.Sizes["bans.db"] == 0 {
		t.Fatalf("tailles : %v", b.Sizes)
	}
	if entries, _ := os.ReadDir(root); func() bool {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), backupTmpPrefix) {
				return true
			}
		}
		return false
	}() {
		t.Fatal("dossier de travail non nettoyé")
	}
}
