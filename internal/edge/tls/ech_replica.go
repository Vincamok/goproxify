// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// ECHReplica est le jeu de clés ECH échangé entre les passerelles d'un groupe HA, toujours
// chiffré par la clé du groupe (il contient les clés privées).
type ECHReplica struct {
	Version int64    `json:"version"`
	Keys    []ECHKey `json:"keys"`
}

var errNoECHReplicaKey = errors.New("ech: clé de réplication absente")

func echReplicaKey(haKey string) [32]byte { return sha256.Sum256([]byte("gpx-ech-replica|" + haKey)) }

func SealECHReplica(r ECHReplica, haKey string) ([]byte, error) {
	if haKey == "" {
		return nil, errNoECHReplicaKey
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	key := echReplicaKey(haKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// OpenECHReplica déchiffre un jeu reçu d'un pair ; échoue si la clé du groupe diffère.
func OpenECHReplica(data []byte, haKey string) (ECHReplica, error) {
	var r ECHReplica
	if haKey == "" {
		return r, errNoECHReplicaKey
	}
	key := echReplicaKey(haKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return r, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return r, err
	}
	if len(data) < gcm.NonceSize() {
		return r, errors.New("ech: jeu trop court")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(plain, &r)
	return r, err
}
