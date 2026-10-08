// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vincamok/goproxify/internal/modules"
)

func registerSSH() {
	Register(modules.Manifest{Type: "ssh_exec", Label: "SSH exec (script on a remote machine)", Fields: []modules.Field{
		{Key: "host", Label: "Host", Placeholder: "10.0.0.1:22", Kind: modules.KindText, Required: true},
		{Key: "user", Label: "User", Placeholder: "deploy", Kind: modules.KindText, Required: true},
		{Key: "private_key", Label: "SSH private key (Ed25519 or RSA)", Kind: modules.KindPassword, Secret: true, Required: true, Multiline: true},
		{Key: "script", Label: "Script to run", Placeholder: "nginx -s reload", Kind: modules.KindText, Required: true, Multiline: true},
		{Key: "host_fingerprint", Label: "Host key fingerprint (optional: SHA256:…, or ignore)", Placeholder: "SHA256:… ou ignore", Kind: modules.KindText},
	}}, newSSHTarget)
}

// sshTarget exécute un script sur une machine distante. Le script reçoit, en variables
// d'environnement : GPX_DOMAIN, GPX_CERT_PEM, GPX_KEY_PEM, GPX_EXPIRES_AT (RFC 3339, UTC).
// Exemple : printf '%s' "$GPX_CERT_PEM" > /etc/ssl/certs/$GPX_DOMAIN.pem && nginx -s reload
type sshTarget struct {
	host, user, privateKey, script, hostFingerprint string
	seen                                            string // empreinte vue pendant la poignée de main (confiance à la première utilisation)
	learned                                         map[string]any
}

// Learned retourne l'empreinte de la clé d'hôte mémorisée à la première connexion réussie.
func (s *sshTarget) Learned() map[string]any { return s.learned }

// hostFingerprintIgnore désactive la vérification de la clé d'hôte (machines éphémères dont la clé change).
const hostFingerprintIgnore = "ignore"

func newSSHTarget(cfg map[string]any, _ Deps) (Target, error) {
	t := &sshTarget{
		host: str(cfg, "host"), user: str(cfg, "user"), privateKey: str(cfg, "private_key"),
		script: str(cfg, "script"), hostFingerprint: strings.TrimSpace(str(cfg, "host_fingerprint")),
	}
	if t.host == "" || t.user == "" || t.script == "" {
		return nil, errors.New("config ssh_exec invalide (host, user, script requis)")
	}
	return t, nil
}

func (s *sshTarget) Deploy(_ context.Context, b Bundle) (string, string) {
	signer, err := ssh.ParsePrivateKey([]byte(s.privateKey))
	if err != nil {
		return "error", "clé privée SSH invalide: " + err.Error()
	}

	clientCfg := &ssh.ClientConfig{
		User:            s.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: s.hostKeyCallback(),
		Timeout:         20 * time.Second,
	}

	host := s.host
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	conn, err := ssh.Dial("tcp", host, clientCfg)
	if err != nil {
		return "error", "connexion SSH échouée: " + err.Error()
	}
	defer conn.Close()
	// Connexion authentifiée : la clé d'hôte vue est retenue (TOFU) si aucune empreinte n'était fixée.
	if s.hostFingerprint == "" && s.seen != "" {
		s.learned = map[string]any{"host_fingerprint": s.seen}
	}

	sess, err := conn.NewSession()
	if err != nil {
		return "error", "session SSH échouée: " + err.Error()
	}
	defer sess.Close()

	var stderr bytes.Buffer
	sess.Stderr = &stderr
	out, err := sess.Output(scriptWithEnv(b, s.script))
	if err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "error", "script SSH échoué: " + errMsg
	}

	outStr := strings.TrimSpace(string(out))
	if len(outStr) > 200 {
		outStr = outStr[:200] + "…"
	}
	if outStr == "" {
		outStr = "ok"
	}
	return "ok", outStr
}

// hostKeyCallback vérifie l'empreinte de la clé d'hôte quand host_fingerprint est renseignée
// (format d'`ssh-keygen -lf` : « SHA256:… »). Sans empreinte, la clé d'hôte n'est pas vérifiée —
// comportement historique, acceptable pour une cible interne mais exposé à un homme du milieu.
func (s *sshTarget) hostKeyCallback() ssh.HostKeyCallback {
	switch s.hostFingerprint {
	case hostFingerprintIgnore:
		return ssh.InsecureIgnoreHostKey() //nolint:gosec // choix explicite de l'opérateur
	case "":
		// Première utilisation : on accepte la clé et on mémorise son empreinte si la connexion aboutit.
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			s.seen = ssh.FingerprintSHA256(key)
			return nil
		}
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if got := ssh.FingerprintSHA256(key); got != s.hostFingerprint {
			return fmt.Errorf("empreinte de la clé d'hôte inattendue (reçue %s, attendue %s) : si la machine a été réinstallée, renseignez la nouvelle empreinte dans la cible, ou « ignore »", got, s.hostFingerprint)
		}
		return nil
	}
}

// scriptWithEnv préfixe le script des variables d'environnement. Elles passent par le script lui-même
// (SetEnv est souvent désactivé côté serveur) et sont citées entre apostrophes : le certificat et la
// clé arrivent tels quels, retours à la ligne compris — le %q de Go, lui, produisait des « \n »
// littéraux que le shell ne transforme pas.
func scriptWithEnv(b Bundle, script string) string {
	return "export GPX_DOMAIN=" + shellQuote(b.Domain) +
		" GPX_EXPIRES_AT=" + shellQuote(b.ExpiresAt.UTC().Format(time.RFC3339)) + "\n" +
		"export GPX_CERT_PEM=" + shellQuote(b.CertPEM) + "\n" +
		"export GPX_KEY_PEM=" + shellQuote(b.KeyPEM) + "\n" +
		script
}

// shellQuote cite s pour un shell POSIX : entre apostrophes, une apostrophe devenant '\”.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
