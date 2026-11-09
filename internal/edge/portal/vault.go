// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

// PersonalLogin est un login manuel : saisi par l'utilisateur, secret dans son coffre. Il se lie à une ou plusieurs
// destinations (catalogue ou cibles personnelles) ; une destination peut en avoir plusieurs (ADR 0025).
type PersonalLogin struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Username   string   `json:"username"`
	Password   string   `json:"password,omitempty"`
	PrivateKey string   `json:"private_key,omitempty"`
	DestIDs    []string `json:"dest_ids,omitempty"`
}

// VaultPayload est le contenu du coffre d'un utilisateur, chiffré avec sa clé : ses logins, et pour chaque destination le
// login qu'il préfère quand plusieurs s'appliquent. Les liaisons des logins préconfigurés sont posées par l'administrateur et
// ne sont pas ici.
type VaultPayload struct {
	Logins   map[string]PersonalLogin `json:"logins"`
	Defaults map[string]string        `json:"defaults,omitempty"` // destination → LoginRef
}

func (p *VaultPayload) normalize() {
	if p.Logins == nil {
		p.Logins = map[string]PersonalLogin{}
	}
	if p.Defaults == nil {
		p.Defaults = map[string]string{}
	}
}

// LinksTo liste les logins personnels liés à une destination.
func (p VaultPayload) LinksTo(destID string) []PersonalLogin {
	var out []PersonalLogin
	for _, l := range p.Logins {
		for _, d := range l.DestIDs {
			if d == destID {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// HashPassword bcrypt pour auth locale.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword vérifie un hash bcrypt.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// DeriveVaultKey dérive une clé AES-256 depuis le mot de passe user + userID.
func DeriveVaultKey(userID, password string) [32]byte {
	r := hkdf.New(sha256.New, []byte(password), []byte("goproxify-portal-vault:"+userID), nil)
	var key [32]byte
	_, _ = io.ReadFull(r, key[:])
	return key
}

// SealVault chiffre le payload avec la clé user.
func SealVault(key [32]byte, payload VaultPayload) ([]byte, error) {
	payload.normalize()
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return encryptWithKey(plain, key)
}

// OpenVault déchiffre le payload. Un coffre à l'ancienne forme (une entrée par destination) se relit comme vide : le
// produit n'est pas déployé, la reprise n'est pas prévue (ADR 0025).
func OpenVault(key [32]byte, blob []byte) (VaultPayload, error) {
	var payload VaultPayload
	if len(blob) == 0 {
		payload.normalize()
		return payload, nil
	}
	plain, err := decryptWithKey(blob, key)
	if err != nil {
		return VaultPayload{}, fmt.Errorf("vault decrypt: %w", err)
	}
	if err := json.Unmarshal(plain, &payload); err != nil {
		return VaultPayload{}, err
	}
	payload.normalize()
	return payload, nil
}

// LoadVault lit le coffre d'un utilisateur.
func LoadVault(store *Store, userID string, key [32]byte) (VaultPayload, error) {
	return OpenVault(key, store.VaultBlob(userID))
}

// UpdateVault lit le coffre, applique fn puis le réécrit scellé. fn qui échoue n'écrit rien.
func UpdateVault(store *Store, userID string, key [32]byte, fn func(*VaultPayload) error) error {
	payload, err := LoadVault(store, userID, key)
	if err != nil {
		return err
	}
	if err := fn(&payload); err != nil {
		return err
	}
	sealed, err := SealVault(key, payload)
	if err != nil {
		return err
	}
	return store.SetVaultBlob(userID, sealed)
}

// VaultLoginMeta : un login personnel sans son secret (pour GET /api/vault).
type VaultLoginMeta struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Username      string   `json:"username"`
	HasPassword   bool     `json:"has_password"`
	HasPrivateKey bool     `json:"has_private_key"`
	DestIDs       []string `json:"dest_ids"`
}

// SharedLoginMeta : un login préconfiguré que l'utilisateur peut employer, sans rien de secret. DestIDs ne liste que les
// destinations qu'il voit.
type SharedLoginMeta struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	DestIDs  []string `json:"dest_ids"`
}

func (l PersonalLogin) meta() VaultLoginMeta {
	d := append([]string{}, l.DestIDs...)
	return VaultLoginMeta{
		ID: l.ID, Name: l.Name, Username: l.Username,
		HasPassword: l.Password != "", HasPrivateKey: l.PrivateKey != "", DestIDs: d,
	}
}

// ListPersonalMeta liste les logins personnels sans leur secret, triés par nom.
func (p VaultPayload) ListPersonalMeta() []VaultLoginMeta {
	out := make([]VaultLoginMeta, 0, len(p.Logins))
	for _, l := range p.Logins {
		out = append(out, l.meta())
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
