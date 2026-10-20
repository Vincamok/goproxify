// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"errors"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// agentLogBatch est le lot de logs d'un conteneur que l'Agent envoie à sa passerelle.
type agentLogBatch struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Entries       []struct {
		T    time.Time `json:"t"`
		Line string    `json:"line"`
	} `json:"entries"`
}

var errAgentLogsBusy = errors.New("file d'écriture des logs pleine, réessayer")

// agentLogDedup retient, par conteneur, l'horodatage de la dernière ligne gardée. Un Agent qui renvoie un lot
// dont l'accusé de réception s'est perdu ne le duplique ainsi pas. En mémoire : après un redémarrage de la
// passerelle, un renvoi isolé peut encore doubler une ligne.
type agentLogDedup struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// since retourne l'horodatage au-delà duquel les lignes sont nouvelles (zéro : toutes).
func (d *agentLogDedup) since(container string) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last[container]
}

func (d *agentLogDedup) advance(container string, t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	if t.After(d.last[container]) {
		d.last[container] = t
	}
}

// storeAgentLogs garde un lot de logs de conteneur dans la base locale, avec les logs système : l'Admin les
// reçoit par le flux numéroté. Les lignes déjà gardées (lot renvoyé) sont écartées par leur horodatage, comparé
// à l'état d'avant le lot pour ne pas écarter deux lignes de même horodatage dans un même lot. Le lot est sur
// disque au retour : c'est l'accusé de réception sur lequel l'Agent avance sa position.
func (s *Server) storeAgentLogs(b agentLogBatch) error {
	seen := s.agentLogs.since(b.ContainerID)
	var newest time.Time
	for _, e := range b.Entries {
		ts := e.T.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		if !seen.IsZero() && !ts.After(seen) {
			continue
		}
		if !s.logStore.Add(logstore.KindSystem, logstore.Entry{
			Ts: ts, Level: "info", Component: "agent", Domain: b.ContainerName, Message: e.Line,
		}) {
			// Les lignes déjà ajoutées comptent comme vues : le renvoi du lot ne les double pas.
			s.agentLogs.advance(b.ContainerID, newest)
			return errAgentLogsBusy
		}
		if ts.After(newest) {
			newest = ts
		}
	}
	s.logStore.Flush()
	if !newest.IsZero() {
		s.agentLogs.advance(b.ContainerID, newest)
	}
	return nil
}
