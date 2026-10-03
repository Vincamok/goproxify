// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
)

// Plus larges plages qu'un ban manuel accepte. Au-delà (un pays, un opérateur), un profil IP avec
// ses sources et sa priorité allow/deny est l'outil adapté ; un ban de /8 couperait des millions
// d'adresses sur une faute de frappe.
const (
	MinBanPrefixV4 = 16
	MinBanPrefixV6 = 32
)

// BanTarget est la cible d'un ban : une adresse ou une plage CIDR, normalisée.
type BanTarget struct {
	// Prefix : la plage (une adresse seule vaut /32 ou /128).
	Prefix netip.Prefix
	// Value : forme à enregistrer et à pousser aux passerelles. Une adresse reste « 203.0.113.9 »,
	// une plage devient l'adresse de réseau (« 203.0.113.7/24 » → « 203.0.113.0/24 ») : deux saisies
	// de la même plage ne créent pas deux bans, et le déban retrouve la valeur exacte.
	Value string
	// IsRange : plage de plusieurs adresses.
	IsRange bool
}

// ErrBanTargetEmpty : aucune cible fournie.
var ErrBanTargetEmpty = errors.New("ip requis")

// ParseBanTarget valide la cible d'un ban : adresse IPv4/IPv6 ou CIDR. Elle refuse une valeur
// illisible (la passerelle l'ignorerait sans rien dire) et une plage trop large (voir MinBanPrefixV4).
func ParseBanTarget(s string) (BanTarget, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return BanTarget{}, ErrBanTargetEmpty
	}
	if strings.Contains(s, "%") {
		return BanTarget{}, fmt.Errorf("IP ou CIDR invalide : %q (zone IPv6 non supportée)", s)
	}
	p, err := ParseTraceTarget(s)
	if err != nil {
		return BanTarget{}, fmt.Errorf("IP ou CIDR invalide : %q", s)
	}
	a := p.Addr()
	t := BanTarget{Prefix: p, IsRange: p.Bits() < a.BitLen()}
	if !t.IsRange {
		t.Value = a.String()
		return t, nil
	}
	min := MinBanPrefixV6
	if a.Is4() {
		min = MinBanPrefixV4
	}
	if p.Bits() < min {
		return BanTarget{}, fmt.Errorf("plage %s trop large (minimum /%d en IPv%s) : pour une plage plus large, utiliser un profil IP",
			p.String(), min, map[bool]string{true: "4", false: "6"}[a.Is4()])
	}
	t.Value = p.String()
	return t, nil
}

// Addresses retourne le nombre d'adresses de la cible (approché au-delà de 2^53, en IPv6).
func (t BanTarget) Addresses() float64 {
	return math.Pow(2, float64(t.Prefix.Addr().BitLen()-t.Prefix.Bits()))
}

// Kind vaut « ip » pour une adresse seule, « cidr » pour une plage.
func (t BanTarget) Kind() string {
	if t.IsRange {
		return "cidr"
	}
	return "ip"
}

// ErrBanLockout : la plage contient l'adresse de la personne qui la bannit.
type ErrBanLockout struct {
	Target    string
	Requester string
}

func (e ErrBanLockout) Error() string {
	return fmt.Sprintf("la plage %s contient votre propre adresse (%s) : elle vous couperait l'accès", e.Target, e.Requester)
}

// CheckBanLockout refuse une plage qui contient l'adresse du demandeur. Une adresse seule n'est pas
// concernée (comportement historique : bannir une IP précise reste de la responsabilité de l'appelant).
func CheckBanLockout(t BanTarget, requesterIP string) error {
	if !t.IsRange {
		return nil
	}
	if TraceMatch(t.Prefix, requesterIP) {
		return ErrBanLockout{Target: t.Value, Requester: requesterIP}
	}
	return nil
}

// PrivateRange indique si la cible est réservée (privée, loopback, lien local) : la passerelle
// n'applique jamais de ban à ces adresses.
func (t BanTarget) PrivateRange() bool {
	a := t.Prefix.Addr()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}
