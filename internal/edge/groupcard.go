// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Fiche du groupe HA (ADR 0014, section 3) : la composition et les domaines du groupe, déclarés par l'Admin. Chaque
// membre en garde une copie locale chiffrée, la rattrape auprès de ses pairs avec le reste de ce que l'Admin pousse
// (pushed_replica.go) et la sert à un Admin qui doit se reconstituer. La version la plus haute l'emporte.

const groupCardPath = "/internal/v1/group-card"

var errStaleGroupCard = errors.New("fiche de groupe plus ancienne que celle que ce membre détient")

type groupCardHolder struct {
	mu   sync.Mutex
	card *edgews.GroupCard
}

func (h *groupCardHolder) get() (edgews.GroupCard, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.card == nil {
		return edgews.GroupCard{}, false
	}
	return *h.card, true
}

func groupCardFilePath() string {
	if p := os.Getenv("GPX_GROUP_CARD_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/group-card.gpx"
}

// applyGroupCard retient la fiche si elle n'est pas plus ancienne que la nôtre. Une fiche de même version est déjà là :
// l'Admin la répète à chaque connexion.
func (s *Server) applyGroupCard(card edgews.GroupCard) error {
	if card.Group == "" {
		return errors.New("fiche de groupe sans nom de groupe")
	}
	s.groupCard.mu.Lock()
	defer s.groupCard.mu.Unlock()
	// Un membre qui change de groupe reçoit la fiche de son nouveau groupe, dont la version repart de la sienne.
	if cur := s.groupCard.card; cur != nil && cur.Group == card.Group {
		if card.Version < cur.Version {
			return errStaleGroupCard
		}
		if card.Version == cur.Version {
			return nil
		}
	}
	if s.cache != nil {
		if err := s.cache.SaveFile(groupCardFilePath(), card); err != nil {
			s.log.Warn("groupe: persistance de la fiche échouée", "group", card.Group, "err", err)
		}
	}
	s.groupCard.card = &card
	s.log.Info("groupe: fiche reçue", "group", card.Group, "version", card.Version, "membres", len(card.Members), "domaines", len(card.Domains))
	return nil
}

// loadGroupCardFromDisk rend à la passerelle sa fiche sans l'Admin.
func (s *Server) loadGroupCardFromDisk() {
	if s.cache == nil {
		return
	}
	var card edgews.GroupCard
	ok, err := s.cache.LoadFile(groupCardFilePath(), &card)
	if err != nil {
		s.log.Warn("groupe: fiche locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok || card.Group == "" {
		return
	}
	s.groupCard.card = &card
	s.log.Info("groupe: fiche chargée depuis le disque", "group", card.Group, "version", card.Version)
}

// groupCardNewer dit si la fiche portée par un document rattrapé auprès d'un pair a une version supérieure à la nôtre :
// la date de réception ne suffit pas pour une fiche, qui a sa propre version.
func (s *Server) groupCardNewer(payload json.RawMessage) bool {
	var card edgews.GroupCard
	if json.Unmarshal(payload, &card) != nil || card.Group == "" {
		return false
	}
	cur, ok := s.groupCard.get()
	return !ok || cur.Group != card.Group || card.Version > cur.Version
}

// GET /internal/v1/group-card : la fiche du groupe de cette passerelle, pour un Admin qui se reconstitue. 404 tant que
// l'Admin n'en a pas poussé.
func (s *Server) handleGroupCard(w http.ResponseWriter, r *http.Request) {
	card, ok := s.groupCard.get()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(card)
}
