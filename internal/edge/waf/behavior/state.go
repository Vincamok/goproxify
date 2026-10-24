// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import "time"

// State est ce que la passerelle conserve du magasin comportemental sur disque (copie chiffrée) pour repartir après un
// redémarrage, sans l'Admin : les notes en cours, l'historique propre des IP et les références apprises.
type State struct {
	SavedAt  time.Time             `json:"saved_at"`
	Profiles HAPayload             `json:"profiles"`
	Trust    map[string]TrustState `json:"trust,omitempty"`
	Refs     RefsState             `json:"refs,omitempty"`
}

// ExportState copie l'état à persister.
func (s *Store) ExportState() State {
	now := s.now()
	return State{SavedAt: now, Profiles: s.Snapshot(), Trust: s.trust.export(now), Refs: s.refs.export()}
}

// ImportState réinjecte un état relu du disque. Ce qui a vieilli entre-temps se périme tout seul : les notes ont une date de
// fin, l'historique propre une rétention, et les références gardent leurs échantillons datés par heure du jour.
func (s *Store) ImportState(st State) {
	now := s.now()
	s.RestoreSnapshot(st.Profiles)
	s.trust.restore(st.Trust, now)
	s.refs.restore(st.Refs)
}

// Forget efface tout ce que le magasin garde d'une IP (profil, historique propre) : ordre d'effacement RGPD.
func (s *Store) Forget(ip string) {
	s.DeleteProfile(ip)
	s.trust.forget(ip)
}
