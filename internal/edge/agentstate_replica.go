// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
)

// Réplication des états complets des Agents entre les passerelles d'un groupe HA (ADR 0014, étape 3). Un état accepté
// par un membre atteint les autres, qui l'appliquent comme si l'Agent le leur avait envoyé : même contrôle des labels,
// même élagage, même génération. Un membre qui revient d'un redémarrage ou d'une panne rattrape les états plus récents
// auprès de ses pairs, sans l'Agent ni l'Admin. Les échanges sont chiffrés par la clé du groupe.

const (
	agentStateReplicaPath     = "/internal/v1/agent/state/replica"
	agentStateReplicaMaxBytes = 32 << 20
	agentStatePushDebounce    = 250 * time.Millisecond
)

// agentStateStore garde, par (Agent, source, scope), le dernier état accepté : c'est ce qu'un pair vient chercher.
type agentStateStore struct {
	mu     sync.Mutex
	states map[string]*agentStatePayload
	hashes map[string]string // clé → contentHash de l'état retenu
}

// contentHash résume les routes d'un état, sans tenir compte de leur ordre ni de la génération.
func (st *agentStatePayload) contentHash() string {
	routes := append([]agentContainerPayload(nil), st.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		a, b := routes[i], routes[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.ContainerID < b.ContainerID
	})
	inactive := append([]inactiveEntry(nil), st.Inactive...)
	sort.Slice(inactive, func(i, j int) bool {
		if inactive[i].Host != inactive[j].Host {
			return inactive[i].Host < inactive[j].Host
		}
		return inactive[i].ContainerID < inactive[j].ContainerID
	})
	b, _ := json.Marshal(struct {
		Routes   []agentContainerPayload `json:"routes"`
		Inactive []inactiveEntry         `json:"inactive"`
	}{routes, inactive})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// put retient l'état s'il est plus récent que celui qu'on a pour cette clé. Rend vrai quand son contenu diffère du
// précédent (ou qu'il n'y en avait pas) : un état identique ne fait que faire avancer la génération.
func (g *agentStateStore) put(st *agentStatePayload) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.states == nil {
		g.states = map[string]*agentStatePayload{}
		g.hashes = map[string]string{}
	}
	cur, ok := g.states[st.key()]
	if ok && cur.Generation >= st.Generation {
		return false
	}
	h := st.contentHash()
	changed := !ok || g.hashes[st.key()] != h
	cp := *st
	g.states[st.key()] = &cp
	g.hashes[st.key()] = h
	return changed
}

// inactiveRow est un conteneur inactif avec l'Agent et la source qui l'ont annoncé.
type inactiveRow struct {
	inactiveEntry
	Agent  string
	Source string
}

// inactive liste les conteneurs inactifs de tous les états retenus, ceux d'un seul Agent si agent n'est pas vide.
func (g *agentStateStore) inactive(agent string) []inactiveRow {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := make([]string, 0, len(g.states))
	for k := range g.states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []inactiveRow
	for _, k := range keys {
		st := g.states[k]
		if agent != "" && st.AgentName != agent {
			continue
		}
		for _, in := range st.Inactive {
			out = append(out, inactiveRow{inactiveEntry: in, Agent: st.AgentName, Source: st.Source})
		}
	}
	return out
}

func (g *agentStateStore) get(key string) (*agentStatePayload, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.states[key]
	return st, ok
}

func (g *agentStateStore) all() []agentStatePayload {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := make([]string, 0, len(g.states))
	for k := range g.states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]agentStatePayload, 0, len(keys))
	for _, k := range keys {
		out = append(out, *g.states[k])
	}
	return out
}

// digest résume le contenu des états connus : deux membres au même condensé n'ont rien à s'échanger, même si leurs
// générations diffèrent (un Agent renvoie son état à chaque scan sans que rien ne change).
func (g *agentStateStore) digest() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := make([]string, 0, len(g.states))
	for k := range g.states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "=" + g.hashes[k] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// agentStatePusher regroupe les envois aux pairs : un état par clé, après un court délai.
type agentStatePusher struct {
	mu    sync.Mutex
	timer *time.Timer
	dirty map[string]bool
}

// scheduleAgentStatePush transmet l'état de cette clé aux pairs du groupe, en regroupant les envois rapprochés.
func (s *Server) scheduleAgentStatePush(key string) {
	r := &s.agentStatePush
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dirty == nil {
		r.dirty = map[string]bool{}
	}
	r.dirty[key] = true
	if r.timer != nil {
		return
	}
	r.timer = time.AfterFunc(agentStatePushDebounce, func() {
		r.mu.Lock()
		keys := r.dirty
		r.dirty, r.timer = nil, nil
		r.mu.Unlock()
		s.pushAgentStates(context.Background(), keys)
	})
}

type agentStateReplica struct {
	States []agentStatePayload `json:"states"`
}

func (s *Server) pushAgentStates(ctx context.Context, keys map[string]bool) {
	peers, key, ok := s.haAgentPeers()
	if !ok || len(peers) == 0 {
		return
	}
	var doc agentStateReplica
	for k := range keys {
		if st, ok := s.agentStates.get(k); ok {
			doc.States = append(doc.States, *st)
		}
	}
	if len(doc.States) == 0 {
		return
	}
	sealed, err := sealAgentStateReplica(doc, key)
	if err != nil {
		s.log.Warn("agents: réplication des états — chiffrement impossible", "err", err)
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, p := range peers {
		p := p
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+agentStateReplicaPath, bytes.NewReader(sealed))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := client.Do(req)
			if err != nil {
				s.log.Debug("agents: réplication des états — pair injoignable", "pair", p.Name, "err", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// syncAgentStateFromPeer tire les états d'un pair du groupe et applique ceux qui sont plus récents que les nôtres.
func (s *Server) syncAgentStateFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+agentStateReplicaPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("If-None-Match", `"`+s.agentStates.digest()+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, agentStateReplicaMaxBytes))
	if err != nil {
		return
	}
	s.mergeAgentStateReplica(data, key, p.Name)
}

// mergeAgentStateReplica applique les états d'un pair qui dépassent ce que ce membre a déjà accepté. Rend le nombre
// d'états appliqués.
func (s *Server) mergeAgentStateReplica(sealed []byte, key, from string) int {
	doc, err := openAgentStateReplica(sealed, key)
	if err != nil {
		s.log.Warn("agents: réplication des états — illisible (clé de groupe différente ?)", "pair", from, "err", err)
		return 0
	}
	applied := 0
	for i := range doc.States {
		st := doc.States[i]
		if res, status, msg := s.acceptAgentState(&st); status == http.StatusOK {
			applied++
			if res.changed {
				s.log.Info("agents: état répliqué depuis un pair du groupe HA", "pair", from, "agent", st.AgentName, "source", st.Source, "scope", st.Scope)
			} else {
				s.log.Debug("agents: état inchangé reçu d'un pair du groupe HA", "pair", from, "agent", st.AgentName, "source", st.Source, "scope", st.Scope)
			}
		} else if status != http.StatusConflict {
			s.log.Warn("agents: état d'un pair refusé", "pair", from, "agent", st.AgentName, "source", st.Source, "err", msg)
		}
	}
	return applied
}

// GET /internal/v1/agent/state/replica : les derniers états acceptés, chiffrés par la clé du groupe. 304 si le
// demandeur a déjà les mêmes générations.
func (s *Server) handleAgentStateReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	digest := s.agentStates.digest()
	if r.Header.Get("If-None-Match") == `"`+digest+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	sealed, err := sealAgentStateReplica(agentStateReplica{States: s.agentStates.all()}, key)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// POST /internal/v1/agent/state/replica : un pair transmet des états (chiffrés) ; ils sont appliqués s'ils sont plus
// récents. Ils ne repartent pas vers les autres : chaque membre reçoit l'envoi de celui qui l'a eu de l'Agent.
func (s *Server) handleAgentStateReplicaImport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, agentStateReplicaMaxBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := openAgentStateReplica(data, key); err != nil {
		http.Error(w, "états illisibles", http.StatusBadRequest)
		return
	}
	s.mergeAgentStateReplica(data, key, "pair")
	w.WriteHeader(http.StatusNoContent)
}

const agentStateReplicaLabel = "gpx-agent-state-replica|"

func sealAgentStateReplica(doc agentStateReplica, haKey string) ([]byte, error) {
	return sealGroupJSON(doc, haKey, agentStateReplicaLabel)
}

func openAgentStateReplica(sealed []byte, haKey string) (agentStateReplica, error) {
	var doc agentStateReplica
	return doc, openGroupJSON(sealed, haKey, agentStateReplicaLabel, &doc)
}
