// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Identifiants HPKE de la config ECH (RFC 9180 / RFC 9849) : DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 avec AES-128-GCM ou ChaCha20-Poly1305.
const (
	echVersion          = 0xfe0d
	echKEMX25519        = 0x0020
	echKDFHKDFSHA256    = 0x0001
	echAEADAES128GCM    = 0x0001
	echAEADChaCha20Poly = 0x0003
	echMaxNameLength    = 64
)

// ECHKey est une clé ECH serveur : sa config publique (ECHConfig, telle que publiée dans le DNS)
// et la clé privée HPKE associée. SendAsRetry n'est vrai que pour la config courante : un client
// dont la config est périmée reçoit celle-là pour réessayer.
type ECHKey struct {
	Config      []byte `json:"config"`
	PrivateKey  []byte `json:"private_key"`
	SendAsRetry bool   `json:"send_as_retry"`
}

// ECHKeySet est le message Admin → passerelle : l'ensemble des clés à accepter. Vide, il
// désactive ECH.
type ECHKeySet struct {
	Keys []ECHKey `json:"keys"`
}

// GenerateECHKey crée une paire X25519 et la config ECH correspondante pour publicName, le nom
// en clair (SNI externe) que voient les observateurs réseau.
func GenerateECHKey(publicName string, configID uint8) (config, privateKey []byte, err error) {
	if err := ValidateECHPublicName(publicName); err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var contents cryptobyte.Builder
	contents.AddUint8(configID)
	contents.AddUint16(echKEMX25519)
	contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(priv.PublicKey().Bytes()) })
	contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, aead := range []uint16{echAEADAES128GCM, echAEADChaCha20Poly} {
			b.AddUint16(echKDFHKDFSHA256)
			b.AddUint16(aead)
		}
	})
	contents.AddUint8(echMaxNameLength)
	contents.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
	contents.AddUint16(0) // aucune extension
	body, err := contents.Bytes()
	if err != nil {
		return nil, nil, err
	}
	var cfg cryptobyte.Builder
	cfg.AddUint16(echVersion)
	cfg.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
	config, err = cfg.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return config, priv.Bytes(), nil
}

// ECHConfigList assemble une ECHConfigList (valeur du paramètre `ech` d'un enregistrement DNS
// HTTPS/SVCB) à partir de configs ECH.
func ECHConfigList(configs ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range configs {
			b.AddBytes(c)
		}
	})
	out, _ := b.Bytes()
	return out
}

// ECHConfigListBase64 est la forme à coller dans `ech="…"` d'un enregistrement HTTPS.
func ECHConfigListBase64(configs ...[]byte) string {
	return base64.StdEncoding.EncodeToString(ECHConfigList(configs...))
}

// ValidateECHPublicName vérifie que le nom externe est un nom DNS plausible (sans wildcard ni IP).
func ValidateECHPublicName(name string) error {
	if name == "" || len(name) > 255 {
		return fmt.Errorf("nom public ECH invalide")
	}
	if strings.ContainsAny(name, " */:@") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || !strings.Contains(name, ".") {
		return fmt.Errorf("nom public ECH invalide : %q", name)
	}
	allDigits := true
	for _, r := range name {
		if r != '.' && (r < '0' || r > '9') {
			allDigits = false
		}
	}
	if allDigits {
		return fmt.Errorf("le nom public ECH ne peut pas être une adresse IP")
	}
	return nil
}

// ECHManager fournit la config TLS du serveur HTTPS avec les clés ECH courantes. Le crypto/tls de
// Go 1.25 n'accepte les clés que dans la Config : on la remplace donc à chaque changement, et
// les connexions déjà établies ne sont pas touchées.
type ECHManager struct {
	mu   sync.RWMutex
	base *tls.Config
	keys []ECHKey
	cur  *tls.Config

	version int64
}

func NewECHManager() *ECHManager { return &ECHManager{} }

// Bind fixe la config TLS de base (sans ECH).
func (m *ECHManager) Bind(base *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.base = base
	m.rebuildLocked()
}

// Set remplace les clés ; une liste vide désactive ECH.
func (m *ECHManager) Set(keys []ECHKey) error {
	for i, k := range keys {
		if len(k.Config) < 4 || len(k.PrivateKey) != 32 {
			return fmt.Errorf("clé ECH %d invalide", i)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append([]ECHKey(nil), keys...)
	m.rebuildLocked()
	return nil
}

// SetStamped applique un jeu venu de l'Admin : la version (ns) n'avance que si le contenu change,
// pour que les membres d'un groupe HA, qui reçoivent le même envoi à des instants différents,
// n'échangent rien de plus.
func (m *ECHManager) SetStamped(keys []ECHKey) error {
	m.mu.RLock()
	same := sameECHKeys(m.keys, keys)
	m.mu.RUnlock()
	if err := m.Set(keys); err != nil {
		return err
	}
	if !same {
		m.mu.Lock()
		m.version = time.Now().UnixNano()
		m.mu.Unlock()
	}
	return nil
}

// Version est l'estampille du jeu de clés courant (0 : jamais reçu).
func (m *ECHManager) Version() int64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// Restore recharge le jeu et sa version depuis le cache local.
func (m *ECHManager) Restore(keys []ECHKey, version int64) error {
	if err := m.Set(keys); err != nil {
		return err
	}
	m.mu.Lock()
	m.version = version
	m.mu.Unlock()
	return nil
}

// Merge applique le jeu d'un pair du groupe HA s'il est plus récent que le jeu local. Retourne vrai
// si les clés ont changé.
func (m *ECHManager) Merge(keys []ECHKey, version int64) (bool, error) {
	for i, k := range keys {
		if len(k.Config) < 4 || len(k.PrivateKey) != 32 {
			return false, fmt.Errorf("clé ECH %d invalide", i)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if version <= m.version {
		return false, nil
	}
	m.version = version
	if sameECHKeys(m.keys, keys) {
		return false, nil
	}
	m.keys = append([]ECHKey(nil), keys...)
	m.rebuildLocked()
	return true, nil
}

func sameECHKeys(a, b []ECHKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].SendAsRetry != b[i].SendAsRetry || !bytes.Equal(a[i].Config, b[i].Config) || !bytes.Equal(a[i].PrivateKey, b[i].PrivateKey) {
			return false
		}
	}
	return true
}

// Keys retourne les clés courantes (cache chiffré de la passerelle) ; nil-safe comme Config.
func (m *ECHManager) Keys() []ECHKey {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ECHKey(nil), m.keys...)
}

// Config retourne la config TLS à utiliser pour une nouvelle connexion.
func (m *ECHManager) Config() *tls.Config {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

func (m *ECHManager) rebuildLocked() {
	if m.base == nil {
		return
	}
	if len(m.keys) == 0 {
		m.cur = m.base
		return
	}
	cfg := m.base.Clone()
	for _, k := range m.keys {
		cfg.EncryptedClientHelloKeys = append(cfg.EncryptedClientHelloKeys, tls.EncryptedClientHelloKey{
			Config: k.Config, PrivateKey: k.PrivateKey, SendAsRetry: k.SendAsRetry,
		})
	}
	m.cur = cfg
}
