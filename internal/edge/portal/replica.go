// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Réplication du magasin du portail entre les passerelles d'un groupe HA.
//
// Chaque donnée réplicable porte une estampille (dernière modification, ns). Deux magasins qui
// échangent leur état convergent : pour chaque clé, la modification la plus récente l'emporte et une
// suppression (pierre tombale) l'emporte sur une valeur plus ancienne. Le catalogue et la liste des
// comptes Admin restent poussés par l'Admin ; l'audit reste local (l'Admin les consolide).
//
// Clés : ua/<user> (partie administrée du compte), uc/<user> (mot de passe et 2FA), v/<user> (coffre),
// p/<user> (cibles perso), f/<user> (favoris), s/<jeton> (session web, en mode « shared » seulement).

func userAdminKey(id string) string { return "ua/" + id }
func userCredKey(id string) string  { return "uc/" + id }
func vaultKey(id string) string     { return "v/" + id }
func personalKey(id string) string  { return "p/" + id }
func favoritesKey(id string) string { return "f/" + id }
func sessionKey(tok string) string  { return "s/" + tok }

// ReplicaState est l'état échangé entre passerelles (toujours chiffré par la clé du groupe).
type ReplicaState struct {
	V         int                         `json:"v"`
	Users     map[string]UserRecord       `json:"users,omitempty"`
	Vaults    map[string][]byte           `json:"vaults,omitempty"`
	Personal  map[string][]PersonalTarget `json:"personal,omitempty"`
	Favorites map[string][]string         `json:"favorites,omitempty"`
	Sessions  map[string]AuthSession      `json:"sessions,omitempty"`
	Stamps    map[string]int64            `json:"stamps,omitempty"`
	Tombs     map[string]int64            `json:"tombs,omitempty"`
}

var errNoReplicaKey = errors.New("portal: clé de réplication absente")

func replicaKey(haKey string) [32]byte { return sha256.Sum256([]byte("gpx-portal-replica|" + haKey)) }

// SealReplica chiffre un état de réplication avec la clé du groupe.
func SealReplica(r ReplicaState, haKey string) ([]byte, error) {
	if haKey == "" {
		return nil, errNoReplicaKey
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return encryptWithKey(plain, replicaKey(haKey))
}

// OpenReplica déchiffre un état de réplication ; échoue si la clé du groupe diffère.
func OpenReplica(data []byte, haKey string) (ReplicaState, error) {
	var r ReplicaState
	if haKey == "" {
		return r, errNoReplicaKey
	}
	plain, err := decryptWithKey(data, replicaKey(haKey))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(plain, &r)
	return r, err
}

// SetOnChange enregistre le rappel appelé (dans sa propre goroutine) après une modification locale
// réplicable ; jamais après une fusion, pour éviter les échanges en boucle.
func (s *Store) SetOnChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

func (s *Store) notify() {
	if s.onChange != nil {
		go s.onChange()
	}
}

// Une estampille est en microsecondes × 1000 + un suffixe propre au magasin : deux magasins ne produisent
// jamais la même valeur, l'ordre est total et la fusion converge même à horloge identique.
func (s *Store) nextStampLocked() int64 {
	n := time.Now().UnixMicro()*1000 + s.stampNode
	if n <= s.lastStamp {
		n = s.lastStamp + 1000
	}
	s.lastStamp = n
	return n
}

func (s *Store) ensureReplicaMapsLocked() {
	if s.snap.Stamps == nil {
		s.snap.Stamps = map[string]int64{}
	}
	if s.snap.Tombs == nil {
		s.snap.Tombs = map[string]int64{}
	}
}

func (s *Store) stampLocked(keys ...string) {
	s.ensureReplicaMapsLocked()
	ts := s.nextStampLocked()
	for _, k := range keys {
		s.snap.Stamps[k] = ts
		delete(s.snap.Tombs, k)
	}
}

func (s *Store) tombLocked(keys ...string) {
	s.ensureReplicaMapsLocked()
	ts := s.nextStampLocked()
	for _, k := range keys {
		delete(s.snap.Stamps, k)
		s.snap.Tombs[k] = ts
	}
}

func (s *Store) persistStampedLocked(keys ...string) error {
	s.stampLocked(keys...)
	err := s.persistLocked()
	if err == nil {
		s.notify()
	}
	return err
}

func (s *Store) persistTombLocked(keys ...string) error {
	s.tombLocked(keys...)
	err := s.persistLocked()
	if err == nil {
		s.notify()
	}
	return err
}

// sameAdminPart compare la partie d'un compte que l'Admin administre.
func sameAdminPart(a, b UserRecord) bool {
	if a.Username != b.Username || a.Status != b.Status || a.InviteTokenHash != b.InviteTokenHash ||
		a.InviteExpires != b.InviteExpires || a.AdminManaged != b.AdminManaged || len(a.Tags) != len(b.Tags) {
		return false
	}
	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	return true
}

func copyAdminPart(dst *UserRecord, src UserRecord) {
	dst.Username, dst.Status, dst.Tags = src.Username, src.Status, append([]string(nil), src.Tags...)
	dst.InviteTokenHash, dst.InviteExpires, dst.AdminManaged = src.InviteTokenHash, src.InviteExpires, src.AdminManaged
	if src.CreatedAt != "" {
		dst.CreatedAt = src.CreatedAt
	}
}

func copyCredPart(dst *UserRecord, src UserRecord) {
	dst.PasswordHash, dst.TOTPSecret, dst.TOTPEnabled = src.PasswordHash, src.TOTPSecret, src.TOTPEnabled
	dst.TOTPPendingSecret, dst.EmailOTPEnabled = src.TOTPPendingSecret, src.EmailOTPEnabled
}

// adoptUnstampedLocked estampe les données d'avant la réplication (à la date de la dernière
// sauvegarde) pour qu'elles puissent être échangées ; les plus récentes modifications les dépassent.
func (s *Store) adoptUnstampedLocked() {
	s.ensureReplicaMapsLocked()
	base := s.snap.SavedAt.UnixMicro() * 1000
	if base <= 0 {
		base = time.Now().UnixMicro() * 1000
	}
	adopt := func(k string) {
		if _, ok := s.snap.Stamps[k]; !ok {
			if _, dead := s.snap.Tombs[k]; !dead {
				s.snap.Stamps[k] = base
			}
		}
	}
	for _, u := range s.snap.Users {
		adopt(userAdminKey(u.ID))
		if u.PasswordHash != "" || u.TOTPSecret != "" || u.TOTPEnabled {
			adopt(userCredKey(u.ID))
		}
	}
	for id := range s.snap.Vaults {
		adopt(vaultKey(id))
	}
	for id, list := range s.snap.Personal {
		if len(list) > 0 {
			adopt(personalKey(id))
		}
	}
	for id, list := range s.snap.Favorites {
		if len(list) > 0 {
			adopt(favoritesKey(id))
		}
	}
	for tok := range s.snap.AuthSessions {
		adopt(sessionKey(tok))
	}
}

// ExportReplica retourne l'état réplicable ; les sessions web n'en font partie que si withSessions.
func (s *Store) ExportReplica(withSessions bool) ReplicaState {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adoptUnstampedLocked()
	r := ReplicaState{
		V:         1,
		Users:     map[string]UserRecord{},
		Vaults:    map[string][]byte{},
		Personal:  map[string][]PersonalTarget{},
		Favorites: map[string][]string{},
		Sessions:  map[string]AuthSession{},
		Stamps:    map[string]int64{},
		Tombs:     map[string]int64{},
	}
	for _, u := range s.snap.Users {
		r.Users[u.ID] = u
	}
	for id, b := range s.snap.Vaults {
		r.Vaults[id] = append([]byte(nil), b...)
	}
	for id, p := range s.snap.Personal {
		r.Personal[id] = append([]PersonalTarget(nil), p...)
	}
	for id, f := range s.snap.Favorites {
		r.Favorites[id] = append([]string(nil), f...)
	}
	now := time.Now()
	if withSessions {
		for tok, sess := range s.snap.AuthSessions {
			if now.Before(sess.Expires) {
				r.Sessions[tok] = sess
			}
		}
	}
	for k, v := range s.snap.Stamps {
		if withSessions || !strings.HasPrefix(k, "s/") {
			r.Stamps[k] = v
		}
	}
	for k, v := range s.snap.Tombs {
		if withSessions || !strings.HasPrefix(k, "s/") {
			r.Tombs[k] = v
		}
	}
	return r
}

func (s *Store) userIndexLocked(id string) int {
	for i := range s.snap.Users {
		if s.snap.Users[i].ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) userIndexByNameLocked(name string) int {
	for i := range s.snap.Users {
		if strings.EqualFold(s.snap.Users[i].Username, name) {
			return i
		}
	}
	return -1
}

// localIsCanonical : le même compte (même nom) existe sous deux identifiants ; celui du compte
// administré par l'Admin l'emporte, sinon le plus ancien.
func localIsCanonical(local, remote UserRecord) bool {
	if local.AdminManaged != remote.AdminManaged {
		return local.AdminManaged
	}
	if local.CreatedAt != remote.CreatedAt && local.CreatedAt != "" && remote.CreatedAt != "" {
		return local.CreatedAt < remote.CreatedAt
	}
	return local.ID < remote.ID
}

// remapUserLocked renomme un compte local (et tout ce qui s'y rattache).
func (s *Store) remapUserLocked(oldID, newID string) {
	if i := s.userIndexLocked(oldID); i >= 0 {
		s.snap.Users[i].ID = newID
	}
	if v, ok := s.snap.Vaults[oldID]; ok {
		s.snap.Vaults[newID] = v
		delete(s.snap.Vaults, oldID)
	}
	if v, ok := s.snap.Personal[oldID]; ok {
		s.snap.Personal[newID] = v
		delete(s.snap.Personal, oldID)
	}
	if v, ok := s.snap.Favorites[oldID]; ok {
		s.snap.Favorites[newID] = v
		delete(s.snap.Favorites, oldID)
	}
	for tok, sess := range s.snap.AuthSessions {
		if sess.UserID == oldID {
			sess.UserID = newID
			s.snap.AuthSessions[tok] = sess
		}
	}
	s.ensureReplicaMapsLocked()
	for _, mk := range []func(string) string{userAdminKey, userCredKey, vaultKey, personalKey, favoritesKey} {
		if v, ok := s.snap.Stamps[mk(oldID)]; ok {
			s.snap.Stamps[mk(newID)] = v
			delete(s.snap.Stamps, mk(oldID))
		}
		if v, ok := s.snap.Tombs[mk(oldID)]; ok {
			s.snap.Tombs[mk(newID)] = v
			delete(s.snap.Tombs, mk(oldID))
		}
	}
}

// MergeReplica fusionne l'état d'une passerelle pair. Retourne vrai si le magasin local a changé.
func (s *Store) MergeReplica(r ReplicaState, withSessions bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adoptUnstampedLocked()
	changed := false

	// Un même compte créé séparément sur chaque passerelle (SSO) porte deux identifiants : on en retient un.
	idMap := map[string]string{}
	for rid, ru := range r.Users {
		if s.userIndexLocked(rid) >= 0 {
			continue
		}
		li := s.userIndexByNameLocked(ru.Username)
		if li < 0 {
			continue
		}
		lu := s.snap.Users[li]
		if localIsCanonical(lu, ru) {
			idMap[rid] = lu.ID
		} else {
			s.remapUserLocked(lu.ID, rid)
			changed = true
		}
	}
	mapID := func(id string) string {
		if m, ok := idMap[id]; ok {
			return m
		}
		return id
	}

	newer := func(remoteKey, localKey string) (int64, bool) {
		rs := r.Stamps[remoteKey]
		return rs, rs > s.snap.Stamps[localKey] && rs > s.snap.Tombs[localKey]
	}

	for rid, ru := range r.Users {
		id := mapID(rid)
		idx := s.userIndexLocked(id)
		if idx < 0 {
			_, okA := newer(userAdminKey(rid), userAdminKey(id))
			if !okA {
				continue
			}
			nu := ru
			nu.ID = id
			s.snap.Users = append(s.snap.Users, nu)
			if s.snap.Personal[id] == nil {
				s.snap.Personal[id] = []PersonalTarget{}
			}
			s.ensureReplicaMapsLocked()
			s.snap.Stamps[userAdminKey(id)] = r.Stamps[userAdminKey(rid)]
			if cs, okC := newer(userCredKey(rid), userCredKey(id)); okC {
				s.snap.Stamps[userCredKey(id)] = cs
			} else {
				copyCredPart(&s.snap.Users[len(s.snap.Users)-1], UserRecord{})
			}
			changed = true
			continue
		}
		u := &s.snap.Users[idx]
		if ts, ok := newer(userAdminKey(rid), userAdminKey(id)); ok {
			copyAdminPart(u, ru)
			s.ensureReplicaMapsLocked()
			s.snap.Stamps[userAdminKey(id)] = ts
			delete(s.snap.Tombs, userAdminKey(id))
			changed = true
		}
		if ts, ok := newer(userCredKey(rid), userCredKey(id)); ok {
			copyCredPart(u, ru)
			s.ensureReplicaMapsLocked()
			s.snap.Stamps[userCredKey(id)] = ts
			delete(s.snap.Tombs, userCredKey(id))
			changed = true
		}
	}

	for rid, blob := range r.Vaults {
		id := mapID(rid)
		if ts, ok := newer(vaultKey(rid), vaultKey(id)); ok {
			s.snap.Vaults[id] = append([]byte(nil), blob...)
			s.snap.Stamps[vaultKey(id)] = ts
			changed = true
		}
	}
	for rid, list := range r.Personal {
		id := mapID(rid)
		if ts, ok := newer(personalKey(rid), personalKey(id)); ok {
			s.snap.Personal[id] = append([]PersonalTarget(nil), list...)
			s.snap.Stamps[personalKey(id)] = ts
			changed = true
		}
	}
	for rid, fav := range r.Favorites {
		id := mapID(rid)
		if ts, ok := newer(favoritesKey(rid), favoritesKey(id)); ok {
			if s.snap.Favorites == nil {
				s.snap.Favorites = map[string][]string{}
			}
			s.snap.Favorites[id] = append([]string(nil), fav...)
			s.snap.Stamps[favoritesKey(id)] = ts
			changed = true
		}
	}
	if withSessions {
		now := time.Now()
		for tok, sess := range r.Sessions {
			if now.After(sess.Expires) {
				continue
			}
			if ts, ok := newer(sessionKey(tok), sessionKey(tok)); ok {
				sess.UserID = mapID(sess.UserID)
				if s.snap.AuthSessions == nil {
					s.snap.AuthSessions = map[string]AuthSession{}
				}
				s.snap.AuthSessions[tok] = sess
				s.snap.Stamps[sessionKey(tok)] = ts
				changed = true
			}
		}
	}

	for key, t := range r.Tombs {
		if strings.HasPrefix(key, "s/") && !withSessions {
			continue
		}
		local := key
		if kind, id, ok := strings.Cut(key, "/"); ok && kind != "s" {
			local = kind + "/" + mapID(id)
		}
		if t <= s.snap.Stamps[local] || t <= s.snap.Tombs[local] {
			continue
		}
		s.ensureReplicaMapsLocked()
		delete(s.snap.Stamps, local)
		s.snap.Tombs[local] = t
		kind, id, _ := strings.Cut(local, "/")
		switch kind {
		case "ua":
			if idx := s.userIndexLocked(id); idx >= 0 {
				s.snap.Users = append(s.snap.Users[:idx], s.snap.Users[idx+1:]...)
			}
		case "s":
			delete(s.snap.AuthSessions, id)
		}
		changed = true
	}

	if !changed {
		return false, nil
	}
	return true, s.persistLocked()
}
