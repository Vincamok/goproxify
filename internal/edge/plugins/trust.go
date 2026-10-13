// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"strings"
)

// Clés de confiance propres à la passerelle. L'Admin vérifie la signature d'un plugin avant de le stocker, mais
// une passerelle qui ne fait confiance qu'à lui exécute ce que lui envoie un Admin compromis. Avec des clés
// épinglées ici, une passerelle refuse tout paquet qui n'est pas signé par l'une d'elles, quel que soit
// l'expéditeur : l'Admin ne peut plus y faire tourner de code qu'il aurait signé lui-même ou qu'il n'aurait pas
// fait signer.
const (
	// TrustedKeysEnv : clés publiques Ed25519 en base64, séparées par des virgules ou des espaces.
	TrustedKeysEnv = "GPX_PLUGIN_TRUSTED_KEYS"
	// TrustedKeysFileEnv : fichier d'une clé par ligne (les lignes vides et les # sont ignorés).
	TrustedKeysFileEnv = "GPX_PLUGIN_TRUSTED_KEYS_FILE"
)

// trust est la configuration d'épinglage d'un gestionnaire. Non épinglé (aucune des deux variables définie) :
// comportement historique, seule l'empreinte est contrôlée.
type trust struct {
	pinned bool
	keys   []ed25519.PublicKey
}

// loadTrust lit les variables d'environnement. Dès qu'une des deux est définie, l'épinglage est actif — même si
// aucune clé ne se laisse lire : une configuration cassée refuse tout plutôt que de désactiver silencieusement la
// vérification.
func loadTrust(log *slog.Logger) trust {
	var t trust
	add := func(entry, src string) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return
		}
		pub, err := ParsePublicKey(entry)
		if err != nil {
			log.Warn("plugins: clé de confiance ignorée", "source", src, "err", err)
			return
		}
		t.keys = append(t.keys, pub)
	}
	if v := strings.TrimSpace(os.Getenv(TrustedKeysEnv)); v != "" {
		t.pinned = true
		for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
			add(e, TrustedKeysEnv)
		}
	}
	if path := strings.TrimSpace(os.Getenv(TrustedKeysFileEnv)); path != "" {
		t.pinned = true
		f, err := os.Open(path)
		if err != nil {
			log.Warn("plugins: fichier de clés de confiance illisible", "file", path, "err", err)
		} else {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if i := strings.IndexByte(line, '#'); i >= 0 {
					line = strings.TrimSpace(line[:i])
				}
				add(line, path)
			}
			f.Close()
		}
	}
	if t.pinned && len(t.keys) == 0 {
		log.Error("plugins: épinglage de clés demandé mais aucune clé valide : aucun plugin ne sera accepté")
	}
	return t
}

// Pinned indique si la passerelle exige une signature d'une clé épinglée.
func (m *Manager) Pinned() bool { return m != nil && m.trust.pinned }

// verify contrôle la signature d'un paquet contre les clés épinglées. Sans épinglage : toujours accepté.
func (m *Manager) verify(pkg Package) error {
	if !m.trust.pinned {
		return nil
	}
	if len(m.trust.keys) == 0 {
		return errors.New("clés de confiance de la passerelle inutilisables : plugin refusé")
	}
	if pkg.Signature == "" {
		return errors.New("signature absente : cette passerelle n'accepte que les plugins signés par une de ses clés épinglées")
	}
	man := pkg.Manifest
	if err := man.Normalize(); err != nil {
		return err
	}
	sha := strings.ToLower(strings.TrimSpace(pkg.SHA256))
	for _, k := range m.trust.keys {
		if Verify(k, man, sha, pkg.Signature) {
			return nil
		}
	}
	return errors.New("signature invalide ou clé non épinglée sur cette passerelle")
}
