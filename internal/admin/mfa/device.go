// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

const TrustedDeviceCookie = "_gpx_device"
const TrustedDeviceTTLDays = 7 // réduit de 30j (L1) — bypass MFA limité

// GenerateDeviceToken génère un token aléatoire pour un appareil de confiance.
// Retourne le token en clair (pour le cookie) et son hash SHA-256 (pour la DB).
func GenerateDeviceToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("device token: %w", err)
	}
	plain = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(h[:])
	return plain, hash, nil
}

// DeviceCookie porte le token d'un appareil de confiance. HttpOnly : un script de la page ne peut pas le lire ; limité
// à /api/v1/auth, il n'accompagne que la connexion. Secure dès que le navigateur parle HTTPS, directement ou derrière un
// reverse proxy (un en-tête forgé ne ferait que rendre le cookie inutilisable en HTTP clair).
func DeviceCookie(r *http.Request, value string) *http.Cookie {
	return &http.Cookie{
		Name:     TrustedDeviceCookie,
		Value:    value,
		Path:     "/api/v1/auth",
		MaxAge:   TrustedDeviceTTLDays * 24 * 3600,
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"),
		SameSite: http.SameSiteStrictMode,
	}
}

// HashDeviceToken calcule le hash SHA-256 d'un token appareil.
func HashDeviceToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}
