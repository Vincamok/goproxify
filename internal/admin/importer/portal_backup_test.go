package importer

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

const (
	pveConfig = `{"url":"https://pve:8006","token_id":"audit@pve!gpx","token_secret":"S3CR3T-PVE"}`
	// Enveloppe d'un login préconfigurable : chiffrée pour la passerelle, jamais lisible de l'Admin.
	loginEnvelope = `{"v":1,"epk":"EPK-DATA","nonce":"NONCE-DATA","ct":"SEALED-ENVELOPE-XYZ"}`
)

func openPortalDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedPortal(t *testing.T, db *sql.DB, nodeKey string) string {
	t.Helper()
	auth.ConfigureNodeTokenKey(nodeKey)
	sealed := auth.SealNodeToken(pveConfig)
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port, tags_json, enabled) VALUES ('d1','edge-a','ssh','web','10.0.0.5',22,'["prod"]',1)`, nil},
		{`INSERT INTO portal_dest_sources (id, edge_name, type, name, config_enc, interval_s, enabled, extra_tags_json, auto_publish, status, created_at, updated_at)
			VALUES ('s1','edge-a','proxmox','pve',?,300,1,'["proxmox"]',0,'ok','2026-11-09 10:00:00','2026-11-09 10:00:00')`, []any{sealed}},
		{`INSERT INTO portal_dest_candidates (id, source_id, edge_name, external_id, name, host, port, tags_json, running, state, dest_id, first_seen, last_seen)
			VALUES ('c1','s1','edge-a','qemu/100','web','10.0.0.5',22,'["prod"]',1,'published','d1','2026-11-09 10:00:00','2026-11-09 10:00:00')`, nil},
		{`INSERT INTO portal_logins (id, edge_name, name, username, secret_sealed, has_password, has_key, all_users, groups_json, tags_json, dest_ids_json, dest_groups_json, enabled, created_at, updated_at)
			VALUES ('l1','edge-a','root-prod','root',?,1,0,0,'["g1"]','["ops"]','["d1"]','[]',1,'2026-11-09 10:00:00','2026-11-09 10:00:00')`, []any{loginEnvelope}},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.q, s.args...); err != nil {
			t.Fatalf("%s : %v", s.q[:40], err)
		}
	}
	return sealed
}

func column(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	var v string
	if err := db.QueryRow(q).Scan(&v); err != nil {
		t.Fatalf("%s : %v", q, err)
	}
	return v
}

func TestPortalSourcesAndLoginsSurviveABackupAndAKeyChange(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-de-test")
	t.Cleanup(func() { auth.ConfigureNodeTokenKey("") })
	src := openPortalDB(t, "src.db")
	sealedA := seedPortal(t, src, "jwt-ancien")

	bk := &Backup{Tables: exportTables(src)}
	RedactSecrets(bk)
	if _, err := AttachSecrets(src, bk, nil, nil); err != nil {
		t.Fatal(err)
	}

	// La section standard ne porte ni les identifiants d'API, ni l'enveloppe d'un login : ils sont vidés.
	standard, _ := json.Marshal(bk.Tables)
	for _, leak := range []string{"S3CR3T-PVE", "SEALED-ENVELOPE-XYZ", strings.TrimPrefix(sealedA, "gpxnt1:")} {
		if strings.Contains(string(standard), leak) {
			t.Fatalf("%q lisible dans la section standard", leak)
		}
	}
	if got := bk.Tables["portal_dest_sources"][0]["config_enc"]; got != "" {
		t.Fatalf("config_enc doit être vidé dans la section standard : %v", got)
	}
	if got := bk.Tables["portal_logins"][0]["secret_sealed"]; got != "" {
		t.Fatalf("secret_sealed doit être vidé dans la section standard : %v", got)
	}
	whole, _ := json.Marshal(bk)
	for _, leak := range []string{"S3CR3T-PVE", "SEALED-ENVELOPE-XYZ"} {
		if strings.Contains(string(whole), leak) {
			t.Fatalf("%q lisible dans le snapshot : la section secrets est chiffrée", leak)
		}
	}

	// Un Admin reconstruit : base vierge et clé de nœud différente (le secret JWT est régénéré).
	dst := openPortalDB(t, "dst.db")
	auth.ConfigureNodeTokenKey("jwt-nouveau")
	res := Apply(dst, bk, ImportSelection{ImportSecrets: true, ImportConfig: true, AllowPrivileged: true, OnConflict: "overwrite"})
	if res.SecretsError != "" {
		t.Fatalf("restauration : %+v", res)
	}

	for table, want := range map[string]string{"portal_destinations": "d1", "portal_dest_candidates": "c1", "portal_dest_sources": "s1", "portal_logins": "l1"} {
		if got := column(t, dst, `SELECT id FROM `+table); got != want {
			t.Errorf("%s non restaurée : %q", table, got)
		}
	}
	stored := column(t, dst, `SELECT config_enc FROM portal_dest_sources WHERE id='s1'`)
	if plain, err := auth.OpenNodeToken(stored); err != nil || plain != pveConfig {
		t.Fatalf("les identifiants d'API doivent se relire avec la clé de l'Admin qui restaure : %v %q", err, plain)
	}
	if stored == sealedA {
		t.Fatal("la valeur doit être rescellée avec la nouvelle clé de nœud, pas recopiée")
	}
	if got := column(t, dst, `SELECT secret_sealed FROM portal_logins WHERE id='l1'`); got != loginEnvelope {
		t.Fatalf("l'enveloppe du login doit revenir à l'identique : %q", got)
	}
	if got := column(t, dst, `SELECT dest_ids_json FROM portal_logins WHERE id='l1'`); got != `["d1"]` {
		t.Fatalf("liaisons : %q", got)
	}
	if got := column(t, dst, `SELECT state FROM portal_dest_candidates WHERE id='c1'`); got != "published" {
		t.Fatalf("candidate : %q", got)
	}
}

func TestStandardRestoreNeverBlanksPortalSecretsInPlace(t *testing.T) {
	t.Cleanup(func() { auth.ConfigureNodeTokenKey("") })
	db := openPortalDB(t, "a.db")
	sealed := seedPortal(t, db, "jwt")

	bk := &Backup{Tables: exportTables(db)}
	RedactSecrets(bk) // section standard : secrets vidés
	if w, _ := applyTables(db, bk.Tables, true, false); w == 0 {
		t.Fatal("rien d'écrit : le test ne vérifie rien")
	}
	if got := column(t, db, `SELECT config_enc FROM portal_dest_sources WHERE id='s1'`); got != sealed {
		t.Fatalf("restaurer la section standard seule ne doit pas effacer les identifiants en place : %q", got)
	}
	if got := column(t, db, `SELECT secret_sealed FROM portal_logins WHERE id='l1'`); got != loginEnvelope {
		t.Fatalf("restaurer la section standard seule ne doit pas effacer le secret d'un login : %q", got)
	}

	// Sur une instance vierge, la section standard seule restaure la description sans les secrets : à ressaisir.
	fresh := openPortalDB(t, "b.db")
	applyTables(fresh, bk.Tables, true, false)
	if got := column(t, fresh, `SELECT name FROM portal_logins WHERE id='l1'`); got != "root-prod" {
		t.Fatalf("description du login non restaurée : %q", got)
	}
	if got := column(t, fresh, `SELECT secret_sealed FROM portal_logins WHERE id='l1'`); got != "" {
		t.Fatalf("sans section secrets, le secret n'est pas restauré : %q", got)
	}
	if got := column(t, fresh, `SELECT config_enc FROM portal_dest_sources WHERE id='s1'`); got != "" {
		t.Fatalf("sans section secrets, les identifiants d'API ne sont pas restaurés : %q", got)
	}
}
