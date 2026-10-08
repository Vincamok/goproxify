// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Signature des paquets (ADR 0008) : Ed25519 sur le manifeste normalisé et l'empreinte du module. La
// signature prouve qui a publié le paquet ; l'empreinte seule n'en prouve que l'intégrité. Elle couvre
// le manifeste en entier — politique d'erreur et limites comprises — pour qu'un manifeste plus permissif
// ne puisse pas être accolé à un module signé.

const signContext = "gpx-plugin-v1\n"

// ManifestDigest est l'empreinte du manifeste normalisé (valeurs par défaut appliquées).
func ManifestDigest(m Manifest) (string, error) {
	if err := m.Normalize(); err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func signedMessage(m Manifest, wasmSHA string) ([]byte, error) {
	md, err := ManifestDigest(m)
	if err != nil {
		return nil, err
	}
	return []byte(signContext + "manifest:" + md + "\nwasm:" + wasmSHA + "\n"), nil
}

// KeyID est l'identifiant court d'une clé publique (8 premiers octets de son SHA-256, en hexadécimal).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// GenerateKey crée une paire de clés de signature.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign signe un paquet et retourne la signature en base64.
func Sign(priv ed25519.PrivateKey, m Manifest, wasmSHA string) (string, error) {
	msg, err := signedMessage(m, wasmSHA)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// Verify indique si sigB64 est une signature valide du paquet par pub.
func Verify(pub ed25519.PublicKey, m Manifest, wasmSHA, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg, err := signedMessage(m, wasmSHA)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// ParsePublicKey lit une clé publique en base64 (32 octets).
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("clé publique illisible : %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("clé publique Ed25519 de 32 octets attendue")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey lit une clé privée en base64 (graine de 32 octets ou clé de 64 octets).
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("clé privée illisible : %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, errors.New("clé privée Ed25519 attendue (32 ou 64 octets)")
}
