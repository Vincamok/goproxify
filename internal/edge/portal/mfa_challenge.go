// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MFAChallenge challenge post-mot-de-passe avant émission du bearer.
type MFAChallenge struct {
	ID              string
	UserID          string
	Username        string
	VaultKeyHex     string
	View            string
	Expires         time.Time
	EmailOTPHash    string
	EmailOTPExpires time.Time
	Failures        int // codes faux déjà présentés
}

// MFAChallengeStore challenges en mémoire (non persistés).
type MFAChallengeStore struct {
	mu   sync.Mutex
	byID map[string]MFAChallenge
}

func NewMFAChallengeStore() *MFAChallengeStore {
	return &MFAChallengeStore{byID: map[string]MFAChallenge{}}
}

func (s *MFAChallengeStore) Put(c MFAChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[c.ID] = c
}

func (s *MFAChallengeStore) Get(id string) (MFAChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return MFAChallenge{}, false
	}
	if time.Now().After(c.Expires) {
		delete(s.byID, id)
		return MFAChallenge{}, false
	}
	return c, true
}

func (s *MFAChallengeStore) Update(c MFAChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[c.ID] = c
}

// MaxChallengeFailures : codes faux qu'un défi accepte avant d'être détruit (il faut alors redonner le mot de passe).
const MaxChallengeFailures = 5

// Fail enregistre un code faux et détruit le défi au-delà du seuil ; retourne true s'il a été détruit. Sans cela un
// code TOTP ou un code reçu par courriel se devinait à volonté pendant la durée de vie du défi.
func (s *MFAChallengeStore) Fail(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return true
	}
	c.Failures++
	if c.Failures >= MaxChallengeFailures {
		delete(s.byID, id)
		return true
	}
	s.byID[id] = c
	return false
}

func (s *MFAChallengeStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

func newMFAChallenge(userID, username string, vaultKey [32]byte) MFAChallenge {
	return MFAChallenge{
		ID:          uuid.NewString(),
		UserID:      userID,
		Username:    username,
		VaultKeyHex: hex.EncodeToString(vaultKey[:]),
		Expires:     time.Now().UTC().Add(MFAChallengeTTL),
	}
}
