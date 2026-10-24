// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

var errNoGroupKey = errors.New("clé de groupe absente")

// sealGroupJSON chiffre un document échangé entre les membres d'un groupe HA (AES-256-GCM). La clé est dérivée de la clé
// du groupe et d'un préfixe propre à chaque document : un document ne se lit pas comme un autre.
func sealGroupJSON(v any, haKey, label string) ([]byte, error) {
	if haKey == "" {
		return nil, errNoGroupKey
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	gcm, err := groupGCM(haKey, label)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func openGroupJSON(sealed []byte, haKey, label string, into any) error {
	if haKey == "" {
		return errNoGroupKey
	}
	gcm, err := groupGCM(haKey, label)
	if err != nil {
		return err
	}
	if len(sealed) < gcm.NonceSize() {
		return fmt.Errorf("document trop court")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, into)
}

func groupGCM(haKey, label string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(label + haKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
