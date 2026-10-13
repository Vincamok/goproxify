// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/pluginlib"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/plugins"
)

// Chaîne complète d'un plugin signé : dépôt HTTP → installation par l'Admin (signature vérifiée contre les clés de
// confiance) → envoi à deux passerelles qui l'installent chiffré et l'exécutent → mise à jour avec rotation de clé
// → clé révoquée → module altéré → redémarrage d'une passerelle sans l'Admin.

// gatewayPusher joue le rôle d'edgews.Manager.PushPlugins : il lit les plugins installés (même requête que
// loadPlugins) et les synchronise sur chaque passerelle.
type gatewayPusher struct {
	db *sql.DB
	gw []*plugins.Manager
}

func (g *gatewayPusher) PushPlugins(ctx context.Context) {
	rows, err := g.db.QueryContext(ctx, `SELECT manifest, sha256, wasm, signature FROM plugins ORDER BY name`)
	if err != nil {
		return
	}
	defer rows.Close()
	var pkgs []plugins.Package
	for rows.Next() {
		var pkg plugins.Package
		var manifest string
		if rows.Scan(&manifest, &pkg.SHA256, &pkg.Wasm, &pkg.Signature) == nil && json.Unmarshal([]byte(manifest), &pkg.Manifest) == nil {
			pkgs = append(pkgs, pkg)
		}
	}
	for _, m := range g.gw {
		m.Sync(ctx, pkgs)
	}
}

func newGateway(t *testing.T, dir string) *plugins.Manager {
	t.Helper()
	m := plugins.NewManager(edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-de-la-passerelle"), filepath.Join(dir, "plugins"), slog.New(slog.DiscardHandler))
	t.Cleanup(func() { m.Close(context.Background()) })
	return m
}

func (g *gatewayPusher) eventually(t *testing.T, what string, cond func(m *plugins.Manager) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok := true
		for _, m := range g.gw {
			if !cond(m) {
				ok = false
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s : état des passerelles non atteint", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func installedSHA(m *plugins.Manager, name string) string {
	if p, ok := m.Get(name); ok {
		return p.SHA256
	}
	return ""
}

func TestPluginChain_SignedRepoToTwoGatewaysWithKeyRotation(t *testing.T) {
	base, ok := pluginlib.Get("path-guard")
	if !ok {
		t.Skip("exemple intégré absent")
	}
	// Un second module qui se comporte comme le premier mais n'a pas les mêmes octets (section personnalisée en fin).
	v2 := append(append([]byte{}, base.Wasm...), 0x00, 0x04, 0x01, 'x', 0x01, 0x02)
	v3 := append(append([]byte{}, base.Wasm...), 0x00, 0x04, 0x01, 'y', 0x03, 0x04)

	pubA, privA, _ := plugins.GenerateKey()
	pubB, privB, _ := plugins.GenerateKey()

	files := map[string][]byte{}
	var entries []map[string]any
	publish := func(version string, wasm []byte, signer ed25519.PrivateKey) {
		m := base.Manifest
		m.Version = version
		sum := sha256.Sum256(wasm)
		sha := hex.EncodeToString(sum[:])
		e := map[string]any{"name": m.Name, "version": version, "manifest": m, "wasm_url": "/pg-" + version + ".wasm", "sha256": sha}
		if signer != nil {
			sig, err := plugins.Sign(signer, m, sha)
			if err != nil {
				t.Fatal(err)
			}
			e["signature"] = sig
		}
		files["/pg-"+version+".wasm"] = wasm
		entries = append(entries, e)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "name": "editeur", "plugins": entries})
			return
		}
		if b, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	pusher := &gatewayPusher{db: db, gw: []*plugins.Manager{newGateway(t, t.TempDir()), newGateway(t, t.TempDir())}}
	ph := &PluginsHandler{DB: db, Log: slog.New(slog.DiscardHandler), Pusher: pusher}
	repos := &PluginReposHandler{DB: db, Log: ph.Log, Plugins: ph}
	keys := &PluginKeysHandler{DB: db, Log: ph.Log}

	repoID := addRepo(t, repos, srv.URL+"/index.json")
	addKeyID := func(pub ed25519.PublicKey) string {
		rec := addKey(t, ph, pub)
		if rec.Code != http.StatusCreated {
			t.Fatalf("clé : %d %s", rec.Code, rec.Body.String())
		}
		return plugins.KeyID(pub)
	}
	install := func(version string) *httptest.ResponseRecorder {
		return rpCall(repos, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": base.Name, "version": version})
	}
	denies := func(m *plugins.Manager) bool {
		p, ok := m.Get(base.Name)
		if !ok {
			return false
		}
		out, err := p.Call(context.Background(), plugins.HookRequest, plugins.RequestInput{Path: "/admin/x", ClientIP: "203.0.113.9", Config: map[string]any{"blocked_prefix": "/admin"}})
		return err == nil && out.Action == plugins.ActionDeny
	}

	// 1. Clé A de confiance, version 1 signée par A : installée et envoyée aux deux passerelles.
	addKeyID(pubA)
	publish("1.0.0", base.Wasm, privA)
	if rec := install("1.0.0"); rec.Code != http.StatusCreated {
		t.Fatalf("installation v1 : %d %s", rec.Code, rec.Body.String())
	}
	pusher.eventually(t, "v1 sur les deux passerelles", func(m *plugins.Manager) bool { return installedSHA(m, base.Name) == base.SHA256 && denies(m) })

	// 2. Rotation : la clé B est ajoutée, la version 2 est signée par B (la clé A reste de confiance : mise à jour).
	idB := addKeyID(pubB)
	publish("1.1.0", v2, privB)
	sumV2 := sha256.Sum256(v2)
	wantV2 := hex.EncodeToString(sumV2[:])
	if rec := install("1.1.0"); rec.Code != http.StatusOK {
		t.Fatalf("mise à jour v2 : %d %s", rec.Code, rec.Body.String())
	}
	pusher.eventually(t, "v2 sur les deux passerelles", func(m *plugins.Manager) bool { return installedSHA(m, base.Name) == wantV2 && denies(m) })

	// 3. La clé A est retirée : une version 3 signée par A est refusée, rien ne change sur les passerelles.
	var idA = plugins.KeyID(pubA)
	keys.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/api/v1/plugin-keys/"+url.PathEscape(idA), nil))
	publish("1.2.0", v3, privA)
	if rec := install("1.2.0"); rec.Code != http.StatusBadRequest {
		t.Fatalf("version signée par une clé retirée : %d, attendu 400 (%s)", rec.Code, rec.Body.String())
	}
	time.Sleep(100 * time.Millisecond)
	for i, m := range pusher.gw {
		if installedSHA(m, base.Name) != wantV2 {
			t.Errorf("passerelle %d : le plugin a changé malgré le refus", i)
		}
	}

	// 4. Module altéré en transit (empreinte annoncée par l'index ≠ octets servis), signature valide de B : refusé.
	v4 := append(append([]byte{}, base.Wasm...), 0x00, 0x04, 0x01, 'z', 0x05, 0x06)
	publish("1.3.0", v4, privB)
	files["/pg-1.3.0.wasm"] = append(append([]byte{}, v4...), 0x00) // un octet de plus que ce qui a été signé
	if rec := install("1.3.0"); rec.Code != http.StatusBadRequest {
		t.Fatalf("module altéré : %d, attendu 400 (%s)", rec.Code, rec.Body.String())
	}

	// 5. Version non signée alors que des clés existent : refusée.
	publish("1.4.0", append(append([]byte{}, base.Wasm...), 0x00, 0x04, 0x01, 'u', 0x07, 0x08), nil)
	if rec := install("1.4.0"); rec.Code != http.StatusBadRequest {
		t.Fatalf("version non signée : %d, attendu 400", rec.Code)
	}
	_ = idB

	// 6. Autonomie : une passerelle redémarre pendant que l'Admin est injoignable — elle recharge le plugin depuis son
	//    stockage chiffré, à la version 2.
	dir := t.TempDir()
	gw := newGateway(t, dir)
	pkgs := []plugins.Package{{Manifest: base.Manifest, SHA256: wantV2, Wasm: v2}}
	pkgs[0].Manifest.Version = "1.1.0"
	if _, _, errs := gw.Sync(context.Background(), pkgs); len(errs) != 0 {
		t.Fatalf("synchronisation : %v", errs)
	}
	gw.Close(context.Background())
	restarted := plugins.NewManager(edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-de-la-passerelle"), filepath.Join(dir, "plugins"), slog.New(slog.DiscardHandler))
	defer restarted.Close(context.Background())
	if n, errs := restarted.LoadAll(context.Background()); n != 1 || len(errs) != 0 {
		t.Fatalf("rechargement : %d plugin(s), erreurs %v", n, errs)
	}
	if !denies(restarted) {
		t.Error("le plugin rechargé après redémarrage ne décide plus comme avant")
	}
	if installedSHA(restarted, base.Name) != wantV2 {
		t.Error("le plugin rechargé n'est pas la version 2")
	}
}

// Une passerelle qui épingle des clés ne fait pas confiance à l'Admin : elle refuse ce qu'il pousse sans signature
// d'une de ses clés, et accepte le même plugin dès qu'il est signé. Une passerelle sans épinglage reçoit tout.
func TestPluginChain_PinnedGatewayDoesNotTrustTheAdmin(t *testing.T) {
	base, ok := pluginlib.Get("path-guard")
	if !ok {
		t.Skip("exemple intégré absent")
	}
	pub, priv, _ := plugins.GenerateKey()
	otherPub, _, _ := plugins.GenerateKey()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	open := newGateway(t, t.TempDir())
	t.Setenv(plugins.TrustedKeysEnv, base64.StdEncoding.EncodeToString(pub))
	pinned := newGateway(t, t.TempDir())
	t.Setenv(plugins.TrustedKeysEnv, base64.StdEncoding.EncodeToString(otherPub))
	pinnedOther := newGateway(t, t.TempDir())
	pusher := &gatewayPusher{db: db, gw: []*plugins.Manager{open, pinned, pinnedOther}}
	ph := &PluginsHandler{DB: db, Log: slog.New(slog.DiscardHandler), Pusher: pusher}

	// 1. Aucune clé côté Admin : l'installation non signée est permise, les passerelles qui épinglent la refusent.
	req := pluginRequest{Manifest: base.Manifest, SHA256: base.SHA256, Wasm: base.Wasm}
	if _, _, ierr := ph.installPackage(context.Background(), req, ""); ierr != nil {
		t.Fatalf("installation non signée : %v", ierr.msg)
	}
	for deadline := time.Now().Add(3 * time.Second); installedSHA(open, base.Name) == "" && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // le temps, pour les passerelles qui épinglent, de refuser
	if installedSHA(open, base.Name) != base.SHA256 {
		t.Error("la passerelle sans épinglage doit recevoir le plugin")
	}
	for name, m := range map[string]*plugins.Manager{"épinglée": pinned, "épinglée sur une autre clé": pinnedOther} {
		if installedSHA(m, base.Name) != "" {
			t.Errorf("passerelle %s : un plugin non signé a été accepté", name)
		}
	}

	// 2. Clé de confiance côté Admin, version signée : la passerelle épinglée sur cette clé l'accepte (et la
	//    signature a bien été stockée puis poussée), celle épinglée sur une autre clé la refuse toujours.
	if rec := addKey(t, ph, pub); rec.Code != http.StatusCreated {
		t.Fatalf("clé : %d %s", rec.Code, rec.Body.String())
	}
	m := base.Manifest
	m.Version = "1.0.1"
	v2 := append(append([]byte{}, base.Wasm...), 0x00, 0x04, 0x01, 'x', 0x01, 0x02)
	sum := sha256.Sum256(v2)
	sha := hex.EncodeToString(sum[:])
	sig, err := plugins.Sign(priv, m, sha)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ierr := ph.installPackage(context.Background(), pluginRequest{Manifest: m, SHA256: sha, Wasm: v2, Signature: sig}, base.Name); ierr != nil {
		t.Fatalf("installation signée : %v", ierr.msg)
	}
	pusher.eventually(t, "version signée", func(g *plugins.Manager) bool {
		if g == pinnedOther {
			return true
		}
		return installedSHA(g, base.Name) == sha
	})
	if info := pinned.List(); len(info) != 1 || !info[0].Verified {
		t.Errorf("passerelle épinglée : %+v", info)
	}
	time.Sleep(100 * time.Millisecond)
	if installedSHA(pinnedOther, base.Name) != "" {
		t.Error("la passerelle épinglée sur une autre clé ne doit rien accepter")
	}
}
