// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

// MinKeyLength : longueur minimale d'une clé saisie à la main.
const MinKeyLength = 16

// ErrKeyFromEnv : la clé active vient de GPX_BACKUP_KEY, l'interface ne peut ni la changer ni la révéler.
var ErrKeyFromEnv = errors.New("la clé est définie par la variable d'environnement GPX_BACKUP_KEY")

type retiredKey struct {
	Key       string    `json:"key"`
	RetiredAt time.Time `json:"retired_at"`
}

type keyFile struct {
	Active  string       `json:"active,omitempty"`
	Retired []retiredKey `json:"retired,omitempty"`
}

// KeyStore conserve, dans un fichier 0600 hors de la base et hors des dossiers repris par les
// snapshots, la clé de chiffrement des sauvegardes saisie ou générée dans l'interface, et les clés
// retirées par une rotation : l'Admin essaie toutes les clés connues pour relire un snapshot, si bien
// qu'une rotation ne rend aucun ancien snapshot illisible. Une clé copiée dans le snapshot qu'elle
// chiffre ne protégerait rien, d'où l'emplacement à part.
type KeyStore struct {
	mu   sync.Mutex
	path string
}

// NewKeyStore cible <dir>/backup-keys.json et charge les clés existantes (reprend l'ancien
// fichier backup.key d'une clé unique).
func NewKeyStore(dir string) *KeyStore {
	ks := &KeyStore{path: filepath.Join(dir, "backup-keys.json")}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, err := os.Stat(ks.path); err != nil {
		if raw, err := os.ReadFile(filepath.Join(dir, "backup.key")); err == nil && strings.TrimSpace(string(raw)) != "" {
			ks.save(keyFile{Active: strings.TrimSpace(string(raw))}) //nolint:errcheck
		}
	}
	ks.apply(ks.load())
	return ks
}

func (k *KeyStore) load() keyFile {
	var f keyFile
	if raw, err := os.ReadFile(k.path); err == nil {
		_ = json.Unmarshal(raw, &f)
	}
	return f
}

func (k *KeyStore) apply(f keyFile) {
	retired := make([]string, 0, len(f.Retired))
	for _, r := range f.Retired {
		retired = append(retired, r.Key)
	}
	importer.SetKeyRing(f.Active, retired)
}

// save écrit atomiquement (0600) et active le trousseau.
func (k *KeyStore) save(f keyFile) error {
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(k.path), ".keys-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), k.path); err != nil {
		return err
	}
	k.apply(f)
	return nil
}

// Fingerprint : empreinte courte, sans danger à afficher, pour reconnaître une clé.
func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])[:8]
}

// GenerateKey renvoie une clé aléatoire de 256 bits.
func GenerateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// RetiredStatus décrit une clé retirée, sans la révéler.
type RetiredStatus struct {
	Fingerprint string    `json:"fingerprint"`
	RetiredAt   time.Time `json:"retired_at"`
}

// KeyStatus décrit les clés en vigueur, sans les révéler.
type KeyStatus struct {
	Source      string          `json:"source"` // env | file | none
	Fingerprint string          `json:"fingerprint,omitempty"`
	CanChange   bool            `json:"can_change"`
	Retired     []RetiredStatus `json:"retired"`
}

// Status renvoie la source, l'empreinte de la clé active et les clés retirées.
func (k *KeyStore) Status() KeyStatus {
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	src := importer.KeySource()
	st := KeyStatus{Source: src, CanChange: src != "env", Retired: []RetiredStatus{}}
	switch src {
	case "env":
		st.Fingerprint = Fingerprint(os.Getenv("GPX_BACKUP_KEY"))
	case "file":
		st.Fingerprint = Fingerprint(f.Active)
	}
	for _, r := range f.Retired {
		st.Retired = append(st.Retired, RetiredStatus{Fingerprint: Fingerprint(r.Key), RetiredAt: r.RetiredAt})
	}
	return st
}

func validKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < MinKeyLength {
		return "", errors.New("clé trop courte (16 caractères au moins)")
	}
	return raw, nil
}

func (f *keyFile) retire(raw string) {
	if raw == "" {
		return
	}
	for _, r := range f.Retired {
		if r.Key == raw {
			return
		}
	}
	f.Retired = append(f.Retired, retiredKey{Key: raw, RetiredAt: time.Now().UTC()})
}

// Set fait de raw la clé active. L'ancienne clé active est conservée parmi les clés retirées : les
// snapshots déjà faits restent lisibles. Renvoie true s'il y a eu rotation.
func (k *KeyStore) Set(raw string) (rotated bool, err error) {
	if importer.KeySource() == "env" {
		return false, ErrKeyFromEnv
	}
	raw, err = validKey(raw)
	if err != nil {
		return false, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	if f.Active == raw {
		return false, nil
	}
	if f.Active != "" {
		f.retire(f.Active)
		rotated = true
	}
	// Une clé redevenue active ne reste pas dans les retirées.
	kept := f.Retired[:0]
	for _, r := range f.Retired {
		if r.Key != raw {
			kept = append(kept, r)
		}
	}
	f.Retired, f.Active = kept, raw
	return rotated, k.save(f)
}

// Deactivate retire la clé active (conservée parmi les clés retirées) : les snapshots suivants seront
// sans secrets.
func (k *KeyStore) Deactivate() error {
	if importer.KeySource() == "env" {
		return ErrKeyFromEnv
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	f.retire(f.Active)
	f.Active = ""
	return k.save(f)
}

// AddRetired ajoute une ancienne clé (par exemple l'ancienne valeur de GPX_BACKUP_KEY) pour relire des
// snapshots qu'elle avait chiffrés.
func (k *KeyStore) AddRetired(raw string) error {
	raw, err := validKey(raw)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	if f.Active != raw {
		f.retire(raw)
	}
	return k.save(f)
}

// ForgetRetired oublie définitivement une clé retirée (les snapshots qu'elle a chiffrés deviennent illisibles).
func (k *KeyStore) ForgetRetired(fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	kept := make([]retiredKey, 0, len(f.Retired))
	found := false
	for _, r := range f.Retired {
		if Fingerprint(r.Key) == fingerprint {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return errors.New("clé retirée introuvable")
	}
	f.Retired = kept
	return k.save(f)
}

// Reveal renvoie la clé active (fingerprint vide) ou une clé retirée. La réauthentification est
// faite par l'appelant.
func (k *KeyStore) Reveal(fingerprint string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.load()
	if fingerprint != "" {
		for _, r := range f.Retired {
			if Fingerprint(r.Key) == fingerprint {
				return r.Key, nil
			}
		}
		if f.Active != "" && Fingerprint(f.Active) == fingerprint && importer.KeySource() != "env" {
			return f.Active, nil
		}
		return "", errors.New("clé introuvable")
	}
	if importer.KeySource() == "env" {
		return "", ErrKeyFromEnv
	}
	if f.Active == "" {
		return "", errors.New("aucune clé enregistrée")
	}
	return f.Active, nil
}
