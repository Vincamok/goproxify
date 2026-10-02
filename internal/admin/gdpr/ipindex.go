// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package gdpr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
)

const ipIndexLabel = "goproxify/gdpr/ip-index/v1"

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
