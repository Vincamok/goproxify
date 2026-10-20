// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ipcrypt fournit les primitives de pseudonymisation RGPD d'une adresse IP : chiffrement AES-GCM,
// empreinte déterministe pour la retrouver, forme canonique. L'Admin les utilise pour ses propres logs
// d'audit, la passerelle pour ses lignes d'accès (ADR 0012).
package ipcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// KeySize est la taille d'une clé AES-256.
const KeySize = 32

const ipIndexLabel = "goproxify/gdpr/ip-index/v1"

// NewKey tire une clé aléatoire de KeySize octets.
func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("ipcrypt: génération clé : %w", err)
	}
	return key, nil
}

// Encrypt chiffre plaintext avec AES-GCM et retourne la valeur encodée en base64.
// Format : nonce(12B) || ciphertext.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt déchiffre une valeur produite par Encrypt.
func Decrypt(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("ipcrypt: décodage base64 : %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", errors.New("ipcrypt: données chiffrées trop courtes")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("ipcrypt: déchiffrement : %w", err)
	}
	return string(plain), nil
}

// IPIndex retourne une empreinte déterministe de l'IP, pour retrouver (et effacer) les
// entrées pseudonymisées d'une IP : Encrypt tire un nonce aléatoire, deux chiffrés de la
// même IP diffèrent. La sous-clé dérivée évite de réutiliser la clé AES telle quelle.
func IPIndex(key []byte, ip string) string {
	sub := hmac.New(sha256.New, key)
	sub.Write([]byte(ipIndexLabel))
	mac := hmac.New(sha256.New, sub.Sum(nil))
	mac.Write([]byte(CanonicalIP(ip)))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// CanonicalIP normalise une adresse (IPv6 compressée en minuscules, IPv4 mappée en IPv4,
// zone retirée) pour que deux écritures d'une même IP aient la même empreinte.
func CanonicalIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return ip
}
