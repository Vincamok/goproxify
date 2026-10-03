// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ech gère les clés ECH (Encrypted Client Hello) du serveur : génération, rotation et
// jeu de clés poussé aux passerelles.
package ech

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

const (
	settingEnabled    = "ech_enabled"
	settingPublicName = "ech_public_name"
)

// Key est une clé ECH stockée. Retired : plus publiée dans le DNS, mais toujours acceptée par
// les passerelles le temps que les caches DNS des clients expirent.
type Key struct {
	ID         string
	ConfigID   uint8
	Config     []byte
	PrivateKey []byte
	PublicName string
	CreatedAt  time.Time
	Retired    bool
}

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Settings retourne l'activation et le nom public configurés.
func (s *Store) Settings() (enabled bool, publicName string) {
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, settingPublicName).Scan(&publicName)
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, settingEnabled).Scan(&v)
	return v == "1", publicName
}

func (s *Store) saveSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`, key, value)
	return err
}

// Configure enregistre l'état voulu. Activer sans clé active, ou changer le nom public (il est
// gravé dans la config publiée), génère une nouvelle clé et retire l'ancienne.
func (s *Store) Configure(enabled bool, publicName string) error {
	if enabled {
		if err := edgetls.ValidateECHPublicName(publicName); err != nil {
			return err
		}
	}
	_, oldName := s.Settings()
	if publicName == "" {
		publicName = oldName
	}
	if err := s.saveSetting(settingEnabled, boolStr(enabled)); err != nil {
		return err
	}
	if err := s.saveSetting(settingPublicName, publicName); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	active, err := s.Active()
	if err != nil {
		return err
	}
	if active == nil || active.PublicName != publicName {
		_, err = s.Rotate(publicName)
	}
	return err
}

// Rotate crée une nouvelle clé active et retire les actives.
func (s *Store) Rotate(publicName string) (*Key, error) {
	keys, err := s.List()
	if err != nil {
		return nil, err
	}
	used := map[uint8]bool{}
	for _, k := range keys {
		used[k.ConfigID] = true
	}
	id, err := freeConfigID(used)
	if err != nil {
		return nil, err
	}
	cfg, priv, err := edgetls.GenerateECHKey(publicName, id)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`UPDATE ech_keys SET retired=1 WHERE retired=0`); err != nil {
		return nil, err
	}
	k := &Key{ID: uuid.NewString(), ConfigID: id, Config: cfg, PrivateKey: priv, PublicName: publicName}
	if _, err := tx.Exec(
		`INSERT INTO ech_keys (id, config_id, config_b64, private_key_b64, public_name) VALUES (?,?,?,?,?)`,
		k.ID, int(id), base64.StdEncoding.EncodeToString(cfg), base64.StdEncoding.EncodeToString(priv), publicName); err != nil {
		return nil, err
	}
	return k, tx.Commit()
}

func freeConfigID(used map[uint8]bool) (uint8, error) {
	for i := 0; i < 1000; i++ {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if !used[b[0]] {
			return b[0], nil
		}
	}
	return 0, fmt.Errorf("aucun identifiant de config ECH libre")
}

// List retourne les clés, la plus récente d'abord.
func (s *Store) List() ([]Key, error) {
	rows, err := s.db.Query(
		`SELECT id, config_id, config_b64, private_key_b64, public_name, created_at, retired
		 FROM ech_keys ORDER BY created_at DESC, rowid DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		var cid, retired int
		var cfgB64, privB64 string
		if err := rows.Scan(&k.ID, &cid, &cfgB64, &privB64, &k.PublicName, &k.CreatedAt, &retired); err != nil {
			return nil, err
		}
		if k.Config, err = base64.StdEncoding.DecodeString(cfgB64); err != nil {
			return nil, err
		}
		if k.PrivateKey, err = base64.StdEncoding.DecodeString(privB64); err != nil {
			return nil, err
		}
		k.ConfigID, k.Retired = uint8(cid), retired == 1
		out = append(out, k)
	}
	return out, rows.Err()
}

// Active retourne la clé publiée dans le DNS, nil s'il n'y en a pas.
func (s *Store) Active() (*Key, error) {
	keys, err := s.List()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if !keys[i].Retired {
			return &keys[i], nil
		}
	}
	return nil, nil
}

// Delete supprime une clé retirée ; la clé active ne peut pas l'être (la désactiver ou la
// remplacer d'abord).
func (s *Store) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM ech_keys WHERE id=? AND retired=1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// PushSet retourne le jeu de clés que les passerelles doivent accepter : toutes les clés quand
// ECH est activé (les retirées déchiffrent encore), la seule clé active en réessai ; vide sinon.
func (s *Store) PushSet() (edgetls.ECHKeySet, error) {
	set := edgetls.ECHKeySet{Keys: []edgetls.ECHKey{}}
	if enabled, _ := s.Settings(); !enabled {
		return set, nil
	}
	keys, err := s.List()
	if err != nil {
		return set, err
	}
	for _, k := range keys {
		set.Keys = append(set.Keys, edgetls.ECHKey{Config: k.Config, PrivateKey: k.PrivateKey, SendAsRetry: !k.Retired})
	}
	return set, nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Status décrit l'état d'ECH tel que l'exposent l'API et le MCP : jamais de clé privée.
func (s *Store) Status() (map[string]any, error) {
	enabled, publicName := s.Settings()
	keys, err := s.List()
	if err != nil {
		return nil, err
	}
	views := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		views = append(views, map[string]any{
			"id": k.ID, "config_id": int(k.ConfigID), "public_name": k.PublicName,
			"created_at": k.CreatedAt, "retired": k.Retired,
		})
	}
	st := map[string]any{"enabled": enabled, "public_name": publicName, "keys": views, "warnings": []string{}}
	if !enabled {
		return st, nil
	}
	for _, k := range keys {
		if k.Retired {
			continue
		}
		list := edgetls.ECHConfigListBase64(k.Config)
		st["active_config_id"] = int(k.ConfigID)
		st["config_list_b64"] = list
		st["https_record"] = `ech="` + list + `"`
		break
	}
	if !s.certCovers(publicName) {
		st["warnings"] = []string{"no_certificate_for_public_name"}
	}
	return st, nil
}

// certCovers indique si un certificat stocké couvre le nom public : sans lui, une passerelle ne
// peut pas présenter de certificat valide quand un client rejette ou rafraîchit sa config ECH.
func (s *Store) certCovers(name string) bool {
	rows, err := s.db.Query(`SELECT domain FROM certs`)
	if err != nil {
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if rows.Scan(&d) != nil {
			continue
		}
		d = strings.ToLower(d)
		if d == name {
			return true
		}
		if strings.HasPrefix(d, "*.") {
			if i := strings.Index(name, "."); i >= 0 && name[i:] == d[1:] {
				return true
			}
		}
	}
	return false
}
