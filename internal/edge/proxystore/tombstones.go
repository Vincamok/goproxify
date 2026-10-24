// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxystore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TombstoneRetention est le temps pendant lequel une suppression est retenue : un membre du groupe HA absent moins
// longtemps l'apprend à son retour. Au-delà, un proxy supprimé pourrait revenir s'il n'a pas été supprimé partout.
const TombstoneRetention = 30 * 24 * time.Hour

const tombstonesFile = "tombstones.json"

var tombMu sync.Mutex

// Tombstones rend les proxys supprimés (identifiant → date de suppression), sans ceux au-delà de la rétention.
func (s *Store) Tombstones() map[string]time.Time {
	tombMu.Lock()
	defer tombMu.Unlock()
	return s.readTombstones()
}

func (s *Store) readTombstones() map[string]time.Time {
	out := map[string]time.Time{}
	b, err := os.ReadFile(filepath.Join(s.basePath, tombstonesFile))
	if err != nil {
		return out
	}
	var raw map[string]time.Time
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	limit := time.Now().Add(-TombstoneRetention)
	for id, at := range raw {
		if at.After(limit) {
			out[id] = at
		}
	}
	return out
}

// RecordTombstone retient la suppression d'un proxy. Une suppression plus ancienne que celle déjà retenue ne la remplace pas.
func (s *Store) RecordTombstone(id string, at time.Time) error {
	tombMu.Lock()
	defer tombMu.Unlock()
	cur := s.readTombstones()
	if prev, ok := cur[id]; ok && !at.After(prev) {
		return nil
	}
	cur[id] = at.UTC()
	return s.writeTombstones(cur)
}

// ClearTombstone oublie la suppression d'un proxy recréé depuis.
func (s *Store) ClearTombstone(id string) error {
	tombMu.Lock()
	defer tombMu.Unlock()
	cur := s.readTombstones()
	if _, ok := cur[id]; !ok {
		return nil
	}
	delete(cur, id)
	return s.writeTombstones(cur)
}

func (s *Store) writeTombstones(m map[string]time.Time) error {
	if err := os.MkdirAll(s.basePath, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	path := filepath.Join(s.basePath, tombstonesFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
