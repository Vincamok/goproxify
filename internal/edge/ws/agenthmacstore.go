// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AgentHMACStore persiste les secrets HMAC des Agents approuvés sur disque.
// Permet aux Agents de se reconnecter sans nouveau JOIN_TOKEN après un redémarrage de la passerelle.
//
// Chaque valeur porte une estampille (ns) et une suppression laisse une pierre tombale : deux
// passerelles d'un groupe HA qui échangent leur état convergent (la modification la plus récente
// l'emporte), de sorte qu'un Agent approuvé sur un membre est accepté par tous.
type AgentHMACStore struct {
	mu       sync.RWMutex
	data     map[string]string // agentID → hmac
	stamps   map[string]int64  // agentID → dernière modification (ns)
	tombs    map[string]int64  // agentID → suppression (ns)
	path     string
	onChange func()
}

// HMACReplica est l'état échangé entre passerelles (toujours chiffré par la clé du groupe).
type HMACReplica struct {
	V      int               `json:"v"`
	Data   map[string]string `json:"data,omitempty"`
	Stamps map[string]int64  `json:"stamps,omitempty"`
	Tombs  map[string]int64  `json:"tombs,omitempty"`
}

// NewAgentHMACStore ouvre ou crée le store de HMACs agents.
func NewAgentHMACStore(path string) *AgentHMACStore {
	s := &AgentHMACStore{
		data:   make(map[string]string),
		stamps: make(map[string]int64),
		tombs:  make(map[string]int64),
		path:   path,
	}
	s.load()
	return s
}

// SetOnChange enregistre le rappel appelé (dans sa propre goroutine) après une modification locale ;
// jamais après une fusion, pour éviter les échanges en boucle.
func (s *AgentHMACStore) SetOnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *AgentHMACStore) notify() {
	s.mu.RLock()
	fn := s.onChange
	s.mu.RUnlock()
	if fn != nil {
		go fn()
	}
}

// Get retourne le HMAC stocké pour un agentID, ou ("", false) s'il n'existe pas.
func (s *AgentHMACStore) Get(agentID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[agentID]
	return v, ok
}

// Set stocke un HMAC et le persiste sur disque.
func (s *AgentHMACStore) Set(agentID, hmac string) error {
	s.mu.Lock()
	s.data[agentID] = hmac
	s.stamps[agentID] = time.Now().UnixNano()
	delete(s.tombs, agentID)
	s.mu.Unlock()
	err := s.save()
	s.notify()
	return err
}

// Delete supprime le HMAC d'un Agent (ex: révocation) et garde une pierre tombale.
func (s *AgentHMACStore) Delete(agentID string) error {
	s.mu.Lock()
	delete(s.data, agentID)
	delete(s.stamps, agentID)
	s.tombs[agentID] = time.Now().UnixNano()
	s.mu.Unlock()
	err := s.save()
	s.notify()
	return err
}

// Export retourne une copie de l'état réplicable.
func (s *AgentHMACStore) Export() HMACReplica {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := HMACReplica{
		V:      1,
		Data:   make(map[string]string, len(s.data)),
		Stamps: make(map[string]int64, len(s.stamps)),
		Tombs:  make(map[string]int64, len(s.tombs)),
	}
	for k, v := range s.data {
		r.Data[k] = v
	}
	for k, v := range s.stamps {
		r.Stamps[k] = v
	}
	for k, v := range s.tombs {
		r.Tombs[k] = v
	}
	return r
}

// Merge fusionne l'état d'un pair : pour chaque agent, la modification la plus récente l'emporte et
// une suppression plus récente que la valeur la retire. Retourne les agents retirés (leurs
// connexions doivent être fermées) ; la sauvegarde n'a lieu que si l'état a changé.
func (s *AgentHMACStore) Merge(r HMACReplica) (changed bool, removed []string, err error) {
	s.mu.Lock()
	for id, hmac := range r.Data {
		at := r.Stamps[id]
		if at <= s.stamps[id] || at <= s.tombs[id] {
			continue
		}
		s.data[id] = hmac
		s.stamps[id] = at
		changed = true
	}
	for id, at := range r.Tombs {
		if at <= s.tombs[id] || at <= s.stamps[id] {
			continue
		}
		if _, had := s.data[id]; had {
			removed = append(removed, id)
		}
		delete(s.data, id)
		delete(s.stamps, id)
		s.tombs[id] = at
		changed = true
	}
	s.mu.Unlock()
	if changed {
		err = s.save()
	}
	return changed, removed, err
}

type hmacFile struct {
	V      int               `json:"v"`
	Data   map[string]string `json:"data"`
	Stamps map[string]int64  `json:"stamps"`
	Tombs  map[string]int64  `json:"tombs"`
}

func (s *AgentHMACStore) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var f hmacFile
	if err := json.Unmarshal(b, &f); err == nil && f.V == 2 {
		if f.Data != nil {
			s.data = f.Data
		}
		if f.Stamps != nil {
			s.stamps = f.Stamps
		}
		if f.Tombs != nil {
			s.tombs = f.Tombs
		}
		return
	}
	// Ancien format : simple table agentID → hmac, sans estampille. Elles valent « maintenant » :
	// un HMAC existant n'est pas écrasé par une valeur répliquée plus ancienne.
	var legacy map[string]string
	if err := json.Unmarshal(b, &legacy); err == nil {
		now := time.Now().UnixNano()
		s.data = legacy
		for id := range legacy {
			s.stamps[id] = now
		}
	}
}

func (s *AgentHMACStore) save() error {
	s.mu.RLock()
	b, err := json.Marshal(hmacFile{V: 2, Data: s.data, Stamps: s.stamps, Tombs: s.tombs})
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("hmac store marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("hmac store mkdir: %w", err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("hmac store write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hmac store rename: %w", err)
	}
	return nil
}
