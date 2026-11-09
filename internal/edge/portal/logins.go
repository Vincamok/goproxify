// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"sort"
	"strings"
)

// Origines d'un login (ADR 0025).
const (
	LoginShared   = "shared"   // préconfiguré par un administrateur, secret scellé pour la passerelle
	LoginPersonal = "personal" // saisi par l'utilisateur, secret dans son coffre
)

// SharedLogin est un login préconfiguré, tel que l'Admin le pousse. Le secret n'y figure que scellé : la passerelle l'ouvre à
// l'usage, l'utilisateur ne le voit jamais.
type SharedLogin struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Sealed   string `json:"sealed,omitempty"`
	// Droit d'usage : AllUsers (tout utilisateur qui voit la destination), sinon les identités de Members (groupes Access
	// développés par l'Admin) ou les utilisateurs qui portent l'une des étiquettes de Tags. Aucun des trois : personne.
	AllUsers bool     `json:"all_users,omitempty"`
	Members  []string `json:"members,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	// DestIDs : destinations du catalogue auxquelles le login est lié (groupes de destinations développés par l'Admin).
	DestIDs []string `json:"dest_ids,omitempty"`
}

// UsableBy dit si l'utilisateur a le droit d'employer ce login. Il ne dit rien de la visibilité de la destination, qui est
// contrôlée à part : un login n'ouvre jamais une destination que l'utilisateur ne voit pas.
func (l SharedLogin) UsableBy(username string, userTags []string) bool {
	if l.AllUsers {
		return true
	}
	username = strings.TrimSpace(username)
	for _, m := range l.Members {
		if strings.EqualFold(strings.TrimSpace(m), username) {
			return true
		}
	}
	if len(l.Tags) == 0 || len(userTags) == 0 {
		return false
	}
	have := make(map[string]bool, len(userTags))
	for _, t := range userTags {
		have[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for _, t := range l.Tags {
		if have[strings.ToLower(strings.TrimSpace(t))] {
			return true
		}
	}
	return false
}

// LinksTo dit si le login est lié à la destination.
func (l SharedLogin) LinksTo(destID string) bool {
	for _, d := range l.DestIDs {
		if d == destID {
			return true
		}
	}
	return false
}

// LoginRef désigne un login de façon non ambiguë : « shared:<id> » ou « personal:<id> ».
func LoginRef(origin, id string) string { return origin + ":" + id }

// ParseLoginRef découpe une référence ; origin vide si elle est mal formée.
func ParseLoginRef(ref string) (origin, id string) {
	origin, id, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok || id == "" || (origin != LoginShared && origin != LoginPersonal) {
		return "", ""
	}
	return origin, id
}

// LoginChoice est un login applicable à une destination, tel que l'interface le propose (jamais de secret).
type LoginChoice struct {
	Ref      string `json:"ref"`
	Origin   string `json:"origin"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Default  bool   `json:"default,omitempty"`
}

func sortChoices(c []LoginChoice) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Default != c[j].Default {
			return c[i].Default
		}
		if c[i].Origin != c[j].Origin {
			return c[i].Origin == LoginShared // les logins préconfigurés d'abord
		}
		return strings.ToLower(c[i].Name) < strings.ToLower(c[j].Name)
	})
}
