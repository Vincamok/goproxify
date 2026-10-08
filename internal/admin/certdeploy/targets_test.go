// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRegistry_ShippedTypes(t *testing.T) {
	var got []string
	for _, m := range Manifests() {
		got = append(got, m.Type)
	}
	if !reflect.DeepEqual(got, []string{"webhook", "ssh_exec"}) {
		t.Fatalf("types = %v", got)
	}
	// pull_token existe en base mais n'est pas une cible que l'Admin exécute.
	if _, ok := ManifestOf("pull_token"); ok {
		t.Fatal("pull_token ne doit pas être un type de cible exécutable")
	}
}

// Les identifiants d'une cible (clé privée SSH, secret HMAC) ne doivent jamais sortir de l'API : avant
// le registre, seul « secret » était masqué et la clé privée SSH était renvoyée en clair.
func TestRegistry_CredentialsAreSecret(t *testing.T) {
	want := map[string][]string{"webhook": {"secret"}, "ssh_exec": {"private_key"}}
	for typ, keys := range want {
		m, _ := ManifestOf(typ)
		var secrets []string
		for _, f := range m.Fields {
			if f.Secret {
				secrets = append(secrets, f.Key)
			}
		}
		if !reflect.DeepEqual(secrets, keys) {
			t.Errorf("%s : secrets = %v, attendu %v", typ, secrets, keys)
		}
	}
}

func TestRegistry_ValidateAcceptsWhatTheFormSends(t *testing.T) {
	web, _ := ManifestOf("webhook")
	if err := web.Validate(map[string]any{"url": "https://h/hook"}); err != nil {
		t.Fatal(err)
	}
	if err := web.Validate(map[string]any{}); err == nil {
		t.Fatal("webhook sans URL accepté")
	}
	sshM, _ := ManifestOf("ssh_exec")
	ok := map[string]any{"host": "h", "user": "u", "private_key": "k", "script": "true"}
	if err := sshM.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"host", "user", "private_key", "script"} {
		cfg := map[string]any{}
		for k, v := range ok {
			if k != missing {
				cfg[k] = v
			}
		}
		if err := sshM.Validate(cfg); err == nil {
			t.Errorf("ssh_exec sans %s accepté", missing)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"simple":     "'simple'",
		"it's":       `'it'\''s'`,
		"a\nb":       "'a\nb'",
		"$(rm -rf)":  "'$(rm -rf)'",
		"`id` \"x\"": "'`id` \"x\"'",
		"":           "''",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, attendu %q", in, got, want)
		}
	}
}

// Des valeurs piégées doivent arriver au script sans être interprétées par le shell.
func TestSSH_HostileValuesAreNotInterpreted(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	if _, err := db.Exec(`UPDATE certs SET cert_pem=?, key_pem=? WHERE id='c1'`, "it's $(touch /tmp/pwned) `id` \"q\"\n", "k\n\n"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := `printf '%s' "$GPX_CERT_PEM" > ` + filepath.ToSlash(dir) + `/c; printf '%s' "$GPX_KEY_PEM" > ` + filepath.ToSlash(dir) + `/k`
	if status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, script)); status != "ok" {
		t.Fatalf("%s %s", status, msg)
	}
	if c, _ := readFile(filepath.Join(dir, "c")); c != "it's $(touch /tmp/pwned) `id` \"q\"\n" {
		t.Errorf("certificat = %q", c)
	}
	if k, _ := readFile(filepath.Join(dir, "k")); k != "k\n\n" {
		t.Errorf("clé = %q", k)
	}
}

func TestSSH_HostFingerprint(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	good := ssh.FingerprintSHA256(f.hostKey)

	cfg := sshCfg(f, `printf ok`)
	cfg["host_fingerprint"] = good
	if status, msg := deploy(t, d, db, "ssh_exec", cfg); status != "ok" || msg != "ok" {
		t.Fatalf("empreinte correcte refusée : %q %q", status, msg)
	}

	cfg["host_fingerprint"] = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	status, msg := deploy(t, d, db, "ssh_exec", cfg)
	if status != "error" || !strings.Contains(msg, "empreinte de la clé d'hôte inattendue") || !strings.Contains(msg, good) {
		t.Fatalf("empreinte erronée acceptée : %q %q", status, msg)
	}

	// Sans empreinte : comportement historique, aucune vérification.
	delete(cfg, "host_fingerprint")
	if status, _ := deploy(t, d, db, "ssh_exec", cfg); status != "ok" {
		t.Fatal("sans empreinte, la connexion doit rester possible")
	}
}

// La clé privée du certificat part dans le corps de la requête : les destinations dangereuses sont
// refusées, mais le réseau interne reste permis (cas normal d'un déploiement).
func TestWebhook_RefusesDangerousDestinations(t *testing.T) {
	d, db := newTestDeployer(t)
	for _, url := range []string{"http://169.254.169.254/latest/meta-data", "file:///etc/passwd", "ftp://h/x"} {
		status, msg := deploy(t, d, db, "webhook", map[string]any{"url": url})
		if status != "error" || !strings.HasPrefix(msg, "URL refusée") {
			t.Errorf("%s : %q %q", url, status, msg)
		}
	}
}

// targetConfig relit la configuration stockée d'une cible.
func targetConfig(t *testing.T, db *sql.DB, id string) map[string]any {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT config FROM cert_deploy_targets WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

// insertTarget enregistre une cible et retourne (id, configuration JSON).
func insertTarget(t *testing.T, db *sql.DB, cfg map[string]any) (string, string) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	id := fmt.Sprintf("tofu-%d", time.Now().UnixNano())
	if _, err := db.Exec(`INSERT INTO cert_deploy_targets (id, cert_id, name, type, config) VALUES (?, 'c1', 'cible', 'ssh_exec', ?)`, id, string(b)); err != nil {
		t.Fatal(err)
	}
	return id, string(b)
}

func lastMessage(t *testing.T, db *sql.DB, id string) (string, string) {
	t.Helper()
	var status, msg string
	if err := db.QueryRow(`SELECT status, message FROM cert_deploy_history WHERE target_id=? ORDER BY rowid DESC LIMIT 1`, id).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	return status, msg
}

// Sans empreinte fixée, la clé d'hôte vue à la première connexion réussie est mémorisée dans la cible ;
// la suivante la vérifie. Un changement de clé (machine usurpée ou réinstallée) fait échouer le déploiement.
func TestSSH_TrustOnFirstUsePinsTheHostKey(t *testing.T) {
	needSh(t)
	first := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	id, cfgJSON := insertTarget(t, db, sshCfg(first, `printf ok`))

	d.runTarget(context.Background(), id, "c1", "ssh_exec", cfgJSON)
	if s, m := lastMessage(t, db, id); s != "ok" {
		t.Fatalf("première connexion : %s %s", s, m)
	}
	want := ssh.FingerprintSHA256(first.hostKey)
	if got := targetConfig(t, db, id)["host_fingerprint"]; got != want {
		t.Fatalf("empreinte mémorisée = %v, attendue %s", got, want)
	}

	// Deuxième déploiement, même machine : accepté (la configuration relue contient l'empreinte).
	var stored string
	_ = db.QueryRow(`SELECT config FROM cert_deploy_targets WHERE id=?`, id).Scan(&stored)
	d.runTarget(context.Background(), id, "c1", "ssh_exec", stored)
	if s, m := lastMessage(t, db, id); s != "ok" {
		t.Fatalf("deuxième connexion : %s %s", s, m)
	}

	// Autre machine derrière la même cible (même clé client, autre clé d'hôte) : refusée.
	second := newFakeSSH(t, true)
	second.clientPK = first.clientPK
	cfg := targetConfig(t, db, id)
	cfg["host"] = second.addr
	b, _ := json.Marshal(cfg)
	d.runTarget(context.Background(), id, "c1", "ssh_exec", string(b))
	s, m := lastMessage(t, db, id)
	if s != "error" || !strings.Contains(m, "empreinte de la clé d'hôte inattendue") {
		t.Fatalf("clé d'hôte changée acceptée : %s %s", s, m)
	}
}

// La mémorisation n'écrase jamais une empreinte fixée par l'opérateur, et « ignore » garde l'ancien
// comportement (aucune vérification, rien de mémorisé).
func TestSSH_ExplicitFingerprintIsNeverOverwritten(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)

	cfg := sshCfg(f, `printf ok`)
	cfg["host_fingerprint"] = "ignore"
	id, cfgJSON := insertTarget(t, db, cfg)
	d.runTarget(context.Background(), id, "c1", "ssh_exec", cfgJSON)
	if s, m := lastMessage(t, db, id); s != "ok" {
		t.Fatalf("ignore : %s %s", s, m)
	}
	if got := targetConfig(t, db, id)["host_fingerprint"]; got != "ignore" {
		t.Fatalf("« ignore » écrasé par %v", got)
	}

	// Échec du script : la connexion a eu lieu, l'empreinte est tout de même mémorisée.
	failing := sshCfg(f, `exit 1`)
	id2, cfgJSON2 := insertTarget(t, db, failing)
	d.runTarget(context.Background(), id2, "c1", "ssh_exec", cfgJSON2)
	if s, _ := lastMessage(t, db, id2); s != "error" {
		t.Fatal("le script devait échouer")
	}
	if got := targetConfig(t, db, id2)["host_fingerprint"]; got != ssh.FingerprintSHA256(f.hostKey) {
		t.Fatalf("empreinte non mémorisée après échec du script : %v", got)
	}

	// Connexion impossible : rien n'est mémorisé.
	down := sshCfg(f, `true`)
	down["host"] = "127.0.0.1:1"
	id3, cfgJSON3 := insertTarget(t, db, down)
	d.runTarget(context.Background(), id3, "c1", "ssh_exec", cfgJSON3)
	if got, ok := targetConfig(t, db, id3)["host_fingerprint"]; ok {
		t.Fatalf("empreinte mémorisée sans connexion : %v", got)
	}
}
