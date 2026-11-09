// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/destsync"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

// Une passerelle sauvegardée puis restaurée sur un volume vierge retrouve ses logins préconfigurés, les coffres de ses
// utilisateurs et ses sources de destinations (ADR 0024, ADR 0025), sans l'Admin : tout vit dans des fichiers chiffrés que la
// sauvegarde reprend déjà (`portal.gpx`, `portal-config.gpx`). Ce test le garantit pour les nouvelles données.
func TestPortalLoginsSourcesAndVaultsSurviveAGatewayBackupAndRestore(t *testing.T) {
	const master = "cle-maitre-test"
	t.Setenv("GPX_PORTAL_MASTER_KEY", master)
	srcDir, dstDir := t.TempDir(), t.TempDir()

	// --- passerelle d'origine --------------------------------------------------------------------------------------------
	t.Setenv("GPX_EDGE_DATA_DIR", srcDir)
	t.Setenv("GPX_PORTAL_CONFIG_PATH", filepath.Join(srcDir, "portal-config.gpx"))
	pub, err := portal.LoginSealPublicKey(master)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := portal.SealLoginSecret(pub, portal.LoginSecret{Password: "TopSecret!", PrivateKey: "PRIVKEY"})
	if err != nil {
		t.Fatal(err)
	}
	payload := portalPushPayload{
		Enabled: true, PublicHost: "access.example.test", SSHPort: freePort(t), HTTPPort: freePort(t),
		DBPath:       filepath.Join(srcDir, "portal.gpx"),
		Catalog:      []portal.CatalogTarget{{ID: "c1", Name: "web", Kind: portal.TargetSSH, Host: "10.0.0.5", Port: 22}},
		SharedLogins: []portal.SharedLogin{{ID: "s1", Name: "root-prod", Username: "root", Sealed: sealed, Tags: []string{"ops"}, DestIDs: []string{"c1"}}},
		DestSources: []destsync.SourceConfig{{ID: "src1", Type: "proxmox", Name: "pve", Enabled: true,
			Config: map[string]any{"url": "https://pve.invalid:8006", "token_id": "audit@pve!gpx", "token_secret": "S3CR3T-PVE"}}},
	}
	s := newPortalGateway(t, srcDir)
	s.applyPortalPush(payload)
	s.portal.Stop()

	// Le coffre d'un utilisateur : un login personnel lié à une destination.
	store := portal.NewStore(payload.DBPath, master)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	hash, _ := portal.HashPassword("password1")
	if err := store.CreateUser(portal.UserRecord{ID: "u1", Username: "a@b.c", PasswordHash: hash, Status: portal.UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	vaultKey := portal.DeriveVaultKey("u1", "password1")
	blob, err := portal.SealVault(vaultKey, portal.VaultPayload{
		Logins:   map[string]portal.PersonalLogin{"l1": {ID: "l1", Name: "moi", Username: "alice", Password: "pw-alice", DestIDs: []string{"c1"}}},
		Defaults: map[string]string{"c1": "personal:l1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetVaultBlob("u1", blob); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	// --- sauvegarde ------------------------------------------------------------------------------------------------------
	rec := httptest.NewRecorder()
	(&Server{}).handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var bundle backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"portal.gpx", "portal-config.gpx"} {
		if len(bundle.Files[want]) == 0 {
			t.Fatalf("%s absent de la sauvegarde de la passerelle : %v", want, keys(bundle.Files))
		}
	}
	for file, data := range bundle.Files {
		for _, leak := range []string{"TopSecret!", "PRIVKEY", "S3CR3T-PVE", "pw-alice"} {
			if bytes.Contains(data, []byte(leak)) {
				t.Fatalf("%q lisible dans %s : les fichiers du portail doivent rester chiffrés", leak, file)
			}
		}
	}

	// --- restauration sur un volume vierge --------------------------------------------------------------------------------
	t.Setenv("GPX_EDGE_DATA_DIR", dstDir)
	t.Setenv("GPX_PORTAL_CONFIG_PATH", filepath.Join(dstDir, "portal-config.gpx"))
	body, _ := json.Marshal(bundle)
	rec = httptest.NewRecorder()
	(&Server{}).handleBackupRestore(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/backup/restore", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("restauration : %d %s", rec.Code, rec.Body.String())
	}

	// Le magasin du portail se relit : logins préconfigurés, secret scellé, coffre de l'utilisateur.
	restored := portal.NewStore(filepath.Join(dstDir, "portal.gpx"), master)
	if err := restored.Load(); err != nil {
		t.Fatalf("magasin restauré illisible : %v", err)
	}
	l, ok := restored.FindSharedLogin("s1")
	if !ok || l.Name != "root-prod" || len(l.DestIDs) != 1 || l.Tags[0] != "ops" {
		t.Fatalf("login préconfiguré restauré : %+v", l)
	}
	secret, err := portal.OpenLoginSecret([]string{master}, l.Sealed)
	if err != nil || secret.Password != "TopSecret!" || secret.PrivateKey != "PRIVKEY" {
		t.Fatalf("le secret scellé doit s'ouvrir après restauration, sans l'Admin : %v %+v", err, secret)
	}
	vault, err := portal.LoadVault(restored, "u1", vaultKey)
	if err != nil {
		t.Fatalf("coffre restauré illisible : %v", err)
	}
	if p := vault.Logins["l1"]; p.Username != "alice" || p.Password != "pw-alice" || len(p.DestIDs) != 1 || vault.Defaults["c1"] != "personal:l1" {
		t.Fatalf("coffre personnel restauré : %+v", vault)
	}
	if _, ok := restored.FindCatalogTarget("c1"); !ok {
		t.Fatal("catalogue restauré")
	}

	// La passerelle redémarre sur sa config : les sources de destinations repartent sans l'Admin.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restarted := newPortalGateway(t, dstDir)
	restarted.destSync = destsync.NewRunner(func(destsync.Inventory) {})
	restarted.destSync.Start(ctx)
	restarted.loadPortalConfigFromDisk()
	defer restarted.portal.Stop()
	if got := restarted.destSync.Active(); len(got) != 1 || got[0] != "src1" {
		t.Fatalf("les sources de destinations doivent repartir après une restauration : %v", got)
	}
	raw, err := os.ReadFile(filepath.Join(dstDir, "portal-config.gpx"))
	if err != nil || strings.Contains(string(raw), "S3CR3T-PVE") {
		t.Fatalf("la copie locale de la config reste chiffrée : %v", err)
	}
}
