// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

const (
	testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\nLINE2\n-----END CERTIFICATE-----\n"
	testKeyPEM  = "-----BEGIN PRIVATE KEY-----\nKEYDATA\nLINE2\n-----END PRIVATE KEY-----\n"
)

// Caractérisation du déploiement de certificats (webhook et ssh_exec). Ce fichier a précédé la
// migration vers le registre de modules : le résultat observable d'un déploiement est le statut et
// le message enregistrés dans l'historique et sur la cible.

func newTestDeployer(t *testing.T) (*Deployer, *sql.DB) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "deploy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO certs (id, domain, issuer, expires_at, cert_pem, key_pem)
		VALUES ('c1', 'app.example.com', 'letsencrypt', '2027-01-02 03:04:05', ?, ?)`, testCertPEM, testKeyPEM); err != nil {
		t.Fatal(err)
	}
	return New(db, slog.New(slog.NewTextHandler(io.Discard, nil))), db
}

// deploy crée une cible, la déclenche de façon synchrone et retourne (statut, message) de l'historique.
func deploy(t *testing.T, d *Deployer, db *sql.DB, typ string, cfg any) (status, message string) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	id := fmt.Sprintf("t-%d", time.Now().UnixNano())
	if _, err := db.Exec(`INSERT INTO cert_deploy_targets (id, cert_id, name, type, config) VALUES (?, 'c1', 'cible', ?, ?)`, id, typ, string(b)); err != nil {
		t.Fatal(err)
	}
	d.runTarget(context.Background(), id, "c1", typ, string(b))
	if err := db.QueryRow(`SELECT status, message FROM cert_deploy_history WHERE target_id=?`, id).Scan(&status, &message); err != nil {
		t.Fatalf("historique : %v", err)
	}
	var last string
	_ = db.QueryRow(`SELECT last_status FROM cert_deploy_targets WHERE id=?`, id).Scan(&last)
	if last != status {
		t.Fatalf("last_status = %q, historique = %q", last, status)
	}
	return status, message
}

// ── Webhook ─────────────────────────────────────────────────────────────────

func TestWebhook_PayloadSignatureAndStatus(t *testing.T) {
	var got webhookPayload
	var sig string
	var rawBody []byte
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		sig = r.Header.Get("X-GoProxify-Signature")
		_ = json.Unmarshal(rawBody, &got)
		w.WriteHeader(code)
	}))
	defer srv.Close()
	d, db := newTestDeployer(t)

	status, msg := deploy(t, d, db, "webhook", map[string]any{"url": srv.URL, "secret": "s3cret"})
	if status != "ok" || msg != "HTTP 200" {
		t.Fatalf("statut %q message %q", status, msg)
	}
	if got.Domain != "app.example.com" || got.CertPEM != testCertPEM || got.KeyPEM != testKeyPEM || got.ChainPEM != testCertPEM {
		t.Fatalf("payload = %+v", got)
	}
	sum := sha256.Sum256([]byte(testCertPEM))
	if got.Fingerprint != hex.EncodeToString(sum[:]) || got.ExpiresAt != "2027-01-02T03:04:05Z" || got.TriggeredAt == "" {
		t.Fatalf("empreinte / dates : %+v", got)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(rawBody)
	if sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature = %q", sig)
	}

	// Sans secret : pas de signature.
	deploy(t, d, db, "webhook", map[string]any{"url": srv.URL})
	if sig != "" {
		t.Fatalf("signature présente sans secret : %q", sig)
	}

	code = http.StatusInternalServerError
	if status, msg := deploy(t, d, db, "webhook", map[string]any{"url": srv.URL}); status != "error" || msg != "HTTP 500" {
		t.Fatalf("HTTP 500 : %q %q", status, msg)
	}
}

func TestWebhook_InvalidConfigAndUnreachable(t *testing.T) {
	d, db := newTestDeployer(t)
	if status, msg := deploy(t, d, db, "webhook", map[string]any{}); status != "error" || msg != "config webhook invalide" {
		t.Fatalf("config vide : %q %q", status, msg)
	}
	status, msg := deploy(t, d, db, "webhook", map[string]any{"url": "http://127.0.0.1:1/hook"})
	if status != "error" || !strings.HasPrefix(msg, "requête échouée") {
		t.Fatalf("injoignable : %q %q", status, msg)
	}
}

func TestDeploy_UnknownTypeAndMissingCert(t *testing.T) {
	d, db := newTestDeployer(t)
	// La base refuse déjà un type inconnu (CHECK) : on appelle donc l'exécution directement.
	d.runTarget(context.Background(), "t-unknown", "c1", "carrier-pigeon", `{}`)
	var status, umsg string
	if err := db.QueryRow(`SELECT status, message FROM cert_deploy_history WHERE target_id='t-unknown'`).Scan(&status, &umsg); err != nil || status != "error" || umsg != "type non supporté: carrier-pigeon" {
		t.Fatalf("type inconnu : %q %q %v", status, umsg, err)
	}
	d.runTarget(context.Background(), "t-x", "absent", "webhook", `{}`)
	var msg string
	if err := db.QueryRow(`SELECT message FROM cert_deploy_history WHERE target_id='t-x'`).Scan(&msg); err != nil || !strings.HasPrefix(msg, "cert introuvable") {
		t.Fatalf("certificat absent : %q %v", msg, err)
	}
}

func TestDeploy_FailureCallback(t *testing.T) {
	d, db := newTestDeployer(t)
	var called string
	d.OnDeployFail = func(targetID, domain, typ, message string) { called = domain + "|" + typ + "|" + message }
	deploy(t, d, db, "webhook", map[string]any{})
	if called != "app.example.com|webhook|config webhook invalide" {
		t.Fatalf("OnDeployFail = %q", called)
	}
}

// ── SSH ─────────────────────────────────────────────────────────────────────

// fakeSSH est un serveur SSH minimal : il authentifie par clé publique, enregistre la commande reçue
// et l'exécute avec sh quand il est disponible (sinon les tests qui en dépendent sont ignorés).
type fakeSSH struct {
	addr     string
	clientPK string // clé privée du client, PEM OpenSSH
	hostKey  ssh.PublicKey
	commands chan string
}

func newFakeSSH(t *testing.T, runWithSh bool) *fakeSSH {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientSSHPub, _ := ssh.NewPublicKey(clientPub)
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), clientSSHPub.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("clé inconnue")
	}}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSSH{addr: ln.Addr().String(), clientPK: string(pem.EncodeToMemory(block)), hostKey: hostSigner.PublicKey(), commands: make(chan string, 8)}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, cfg, runWithSh)
		}
	}()
	return f
}

func (f *fakeSSH) serve(c net.Conn, cfg *ssh.ServerConfig, runWithSh bool) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session seulement") //nolint:errcheck
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				if r.Type != "exec" {
					r.Reply(false, nil) //nolint:errcheck
					continue
				}
				var p struct{ Command string }
				ssh.Unmarshal(r.Payload, &p) //nolint:errcheck
				r.Reply(true, nil)           //nolint:errcheck
				f.commands <- p.Command
				code := uint32(0)
				if runWithSh {
					cmd := exec.Command("sh", "-c", p.Command)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					if err := cmd.Run(); err != nil {
						code = 1
					}
					ch.Write(stdout.Bytes())          //nolint:errcheck
					ch.Stderr().Write(stderr.Bytes()) //nolint:errcheck
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code})) //nolint:errcheck
				return
			}
		}()
	}
}

func needSh(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh indisponible : exécution du script non testable ici")
	}
}

func sshCfg(f *fakeSSH, script string) map[string]any {
	return map[string]any{"host": f.addr, "user": "deploy", "private_key": f.clientPK, "script": script}
}

func TestSSH_RunsScriptAndReportsOutput(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, `printf 'deployed %s' "$GPX_DOMAIN"`))
	if status != "ok" || msg != "deployed app.example.com" {
		t.Fatalf("statut %q message %q", status, msg)
	}
	if status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, `true`)); status != "ok" || msg != "ok" {
		t.Fatalf("sortie vide : %q %q", status, msg)
	}
	long := deployMsg(t, d, db, sshCfg(f, `printf 'x%.0s' $(seq 1 300)`))
	if len(long) > 205 || !strings.HasSuffix(long, "…") {
		t.Fatalf("sortie longue non tronquée : %d octets", len(long))
	}
}

func deployMsg(t *testing.T, d *Deployer, db *sql.DB, cfg any) string {
	_, msg := deploy(t, d, db, "ssh_exec", cfg)
	return msg
}

func TestSSH_ScriptFailureReportsStderr(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, `echo "reload impossible" >&2; exit 3`))
	if status != "error" || msg != "script SSH échoué: reload impossible" {
		t.Fatalf("statut %q message %q", status, msg)
	}
}

func TestSSH_ConfigErrors(t *testing.T) {
	f := newFakeSSH(t, false)
	d, db := newTestDeployer(t)
	if status, msg := deploy(t, d, db, "ssh_exec", map[string]any{"host": f.addr}); status != "error" || msg != "config ssh_exec invalide (host, user, script requis)" {
		t.Fatalf("config incomplète : %q %q", status, msg)
	}
	bad := sshCfg(f, "true")
	bad["private_key"] = "pas une clé"
	if status, msg := deploy(t, d, db, "ssh_exec", bad); status != "error" || !strings.HasPrefix(msg, "clé privée SSH invalide") {
		t.Fatalf("clé invalide : %q %q", status, msg)
	}
	down := sshCfg(f, "true")
	down["host"] = "127.0.0.1:1"
	if status, msg := deploy(t, d, db, "ssh_exec", down); status != "error" || !strings.HasPrefix(msg, "connexion SSH échouée") {
		t.Fatalf("hôte injoignable : %q %q", status, msg)
	}
}

// Le certificat et la clé doivent arriver au script tels quels, retours à la ligne compris : c'est ce
// que promet l'exemple de l'interface (`echo "$GPX_CERT_PEM" > /etc/ssl/certs/$GPX_DOMAIN.pem`).
func TestSSH_PEMReachesTheScriptIntact(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	dir := t.TempDir()
	script := fmt.Sprintf(`printf '%%s' "$GPX_CERT_PEM" > %[1]s/cert.pem; printf '%%s' "$GPX_KEY_PEM" > %[1]s/key.pem`, filepath.ToSlash(dir))
	if status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, script)); status != "ok" {
		t.Fatalf("statut %q message %q", status, msg)
	}
	for name, want := range map[string]string{"cert.pem": testCertPEM, "key.pem": testKeyPEM} {
		b, err := readFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if b != want {
			t.Errorf("%s = %q, attendu %q", name, b, want)
		}
	}
}

// GPX_EXPIRES_AT est documenté dans l'interface ; il doit contenir l'expiration du certificat.
func TestSSH_ExpiresAtIsExported(t *testing.T) {
	needSh(t)
	f := newFakeSSH(t, true)
	d, db := newTestDeployer(t)
	status, msg := deploy(t, d, db, "ssh_exec", sshCfg(f, `printf '%s' "$GPX_EXPIRES_AT"`))
	if status != "ok" || msg != "2027-01-02T03:04:05Z" {
		t.Fatalf("GPX_EXPIRES_AT = %q (%s)", msg, status)
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
