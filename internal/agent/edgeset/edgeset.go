// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package edgeset tient les adresses de passerelle qu'un Agent peut utiliser : celle de sa
// configuration, puis les autres membres de son groupe HA annoncés par sa passerelle. Si la
// passerelle courante tombe, l'Agent bascule vers la suivante. La liste est conservée sur le disque :
// un Agent redémarré pendant la panne de sa passerelle connaît encore les autres membres.
package edgeset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Set est la liste ordonnée des passerelles utilisables et la passerelle courante.
type Set struct {
	mu      sync.RWMutex
	primary string
	others  []string
	cur     int // 0 = primary, i>0 = others[i-1]
	path    string
}

// New crée l'ensemble avec la passerelle configurée en tête et relit les autres membres connus.
// path peut être vide (pas de persistance).
func New(primary, path string) *Set {
	s := &Set{primary: normalize(primary), path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var list []string
			if json.Unmarshal(b, &list) == nil {
				s.others = s.clean(list)
			}
		}
	}
	return s
}

func normalize(ep string) string { return strings.TrimRight(strings.TrimSpace(ep), "/") }

// clean normalise, déduplique et retire la passerelle configurée de la liste des autres.
func (s *Set) clean(list []string) []string {
	seen := map[string]bool{s.primary: true}
	var out []string
	for _, ep := range list {
		ep = normalize(ep)
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		out = append(out, ep)
	}
	return out
}

// Current retourne la passerelle à utiliser maintenant.
func (s *Set) Current() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.at(s.cur)
}

func (s *Set) at(i int) string {
	if i <= 0 || i > len(s.others) {
		return s.primary
	}
	return s.others[i-1]
}

// Len retourne le nombre de passerelles connues, la configurée comprise.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.others)
	if s.primary != "" {
		n++
	}
	return n
}

// Rotate passe à la passerelle suivante (en boucle) et la retourne. Sans autre passerelle connue,
// il n'y a nulle part où basculer : la courante est retournée et changed est faux.
func (s *Set) Rotate() (ep string, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := len(s.others) + 1
	if total <= 1 {
		return s.at(s.cur), false
	}
	s.cur = (s.cur + 1) % total
	return s.at(s.cur), true
}

// Update remplace la liste des autres membres par celle annoncée par la passerelle et la conserve.
// La passerelle annonce les autres membres, pas elle-même : la courante est donc toujours gardée,
// et l'Agent ne repart pas vers la passerelle configurée (peut-être tombée) à chaque annonce. Une
// liste vide est ignorée : un membre qui ne voit plus le groupe n'efface pas ce que l'on en sait.
func (s *Set) Update(list []string) {
	s.mu.Lock()
	cur := s.at(s.cur)
	if len(s.clean(list)) > 0 {
		list = append(append([]string(nil), list...), cur)
	}
	next := s.clean(list)
	if len(next) == 0 {
		s.mu.Unlock()
		return
	}
	s.others = next
	s.cur = 0
	for i, ep := range next {
		if ep == cur {
			s.cur = i + 1
		}
	}
	snapshot := append([]string(nil), s.others...)
	path := s.path
	s.mu.Unlock()

	if path == "" {
		return
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}
