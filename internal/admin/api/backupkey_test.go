package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/backup"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/importer"
)

func newKeyHandler(t *testing.T) (*BackupHandler, http.Handler, map[string]string) {
	t.Helper()
	t.Setenv("GPX_BACKUP_KEY", "")
	importer.SetKeyRing("", nil)
	t.Cleanup(func() { importer.SetKeyRing("", nil) })
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hash, _ := adminauth.HashPassword("mot-de-passe-super")
	db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('su','su@x.fr',?, 'superadmin'), ('ad','ad@x.fr',?, 'admin')`, hash, hash)
	h := &BackupHandler{DB: db, Log: log, Scheduler: backup.New(db, log), Keys: backup.NewKeyStore(t.TempDir())}
	const secret = "jwt-secret-de-test"
	tokens := map[string]string{}
	for id := range map[string]bool{"su": true, "ad": true} {
		tok, err := adminauth.SignJWT(id, secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = tok
	}
	return h, adminauth.RequireJWT(secret)(h), tokens
}

func call(h http.Handler, tok, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBackupKeyAPIAccessRotationAndReveal(t *testing.T) {
	_, h, tok := newKeyHandler(t)

	if rec := call(h, tok["ad"], http.MethodPost, "/api/v1/backups/key", `{"action":"generate"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("un admin a pu créer la clé : %d", rec.Code)
	}
	rec := call(h, tok["su"], http.MethodPost, "/api/v1/backups/key", `{"action":"generate"}`)
	var gen struct {
		Key         string `json:"key"`
		Fingerprint string `json:"fingerprint"`
		Rotated     bool   `json:"rotated"`
	}
	json.Unmarshal(rec.Body.Bytes(), &gen)
	if rec.Code != http.StatusOK || gen.Key == "" || gen.Rotated {
		t.Fatalf("génération : %d %s", rec.Code, rec.Body.String())
	}

	// Le statut ne contient jamais la clé.
	rec = call(h, tok["ad"], http.MethodGet, "/api/v1/backups/key", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), gen.Key) || !strings.Contains(rec.Body.String(), gen.Fingerprint) {
		t.Fatalf("statut : %d %s", rec.Code, rec.Body.String())
	}

	// Révélation : superadmin + mot de passe.
	if rec := call(h, tok["ad"], http.MethodPost, "/api/v1/backups/key/reveal", `{"password":"mot-de-passe-super"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("révélation par un admin : %d", rec.Code)
	}
	if rec := call(h, tok["su"], http.MethodPost, "/api/v1/backups/key/reveal", `{"password":"faux"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("mauvais mot de passe accepté : %d", rec.Code)
	}
	rec = call(h, tok["su"], http.MethodPost, "/api/v1/backups/key/reveal", `{"password":"mot-de-passe-super"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), gen.Key) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("révélation : %d %s", rec.Code, rec.Body.String())
	}

	// Rotation : l'ancienne clé devient révélable par empreinte.
	rec = call(h, tok["su"], http.MethodPut, "/api/v1/backups/key", `{"key":"une-autre-cle-assez-longue"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"rotated":true`) {
		t.Fatalf("rotation : %d %s", rec.Code, rec.Body.String())
	}
	rec = call(h, tok["su"], http.MethodPost, "/api/v1/backups/key/reveal", `{"password":"mot-de-passe-super","fingerprint":"`+gen.Fingerprint+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), gen.Key) {
		t.Fatalf("révélation d'une clé retirée : %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(h, tok["su"], http.MethodDelete, "/api/v1/backups/key/retired/"+gen.Fingerprint, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("oubli d'une clé retirée : %d", rec.Code)
	}

	// Avec GPX_BACKUP_KEY, l'interface ne change ni ne révèle la clé active.
	t.Setenv("GPX_BACKUP_KEY", "cle-de-lenvironnement")
	if rec := call(h, tok["su"], http.MethodPut, "/api/v1/backups/key", `{"key":"encore-une-cle-assez-longue"}`); rec.Code != http.StatusConflict {
		t.Fatalf("changement malgré l'environnement : %d", rec.Code)
	}
	if rec := call(h, tok["su"], http.MethodPost, "/api/v1/backups/key/reveal", `{"password":"mot-de-passe-super"}`); rec.Code != http.StatusConflict {
		t.Fatalf("révélation de la clé d'environnement : %d", rec.Code)
	}
}
