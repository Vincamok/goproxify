// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Actions uniques d'un groupe HA (ADR 0014, section 7). Raft ne convient pas à un groupe de deux (plus de majorité à la
// chute d'un membre) : l'exécutant est le **premier membre de la fiche vu vivant**. Chaque membre le calcule seul, avec
// ce qu'il sait de ses pairs ; dans une partition réseau deux membres peuvent se croire exécutant, ce que les actions
// concernées acceptent (un doublon rare).
//
// Seule action concernée aujourd'hui : la notification d'une règle automatique. Les règles s'évaluent sur les données de
// chaque membre ; un même incident déclenchait donc une notification par membre. Un membre qui n'est pas l'exécutant
// transmet le déclenchement à l'exécutant, qui le remonte à l'Admin une seule fois par fenêtre ; si l'exécutant ne
// répond pas, il le remonte lui-même (une alerte n'est jamais perdue pour éviter un doublon). Le ban et la désactivation
// d'un proxy restent locaux : ils sont idempotents et les bans se répliquent déjà.

const (
	groupRuleFiredPath  = "/internal/v1/group/rule-fired"
	groupRuleFiredLabel = "gpx-rule-fired|"
	// peerAliveFor : un pair est vu vivant s'il a répondu à l'un des derniers échanges (un tous les 15 s).
	peerAliveFor = 45 * time.Second
	// ruleReportWindow : deux déclenchements de la même règle plus rapprochés que cela sont le même incident vu par deux
	// membres (le moteur évalue chaque minute, sur des horloges indépendantes).
	ruleReportWindow = 90 * time.Second
)

// peerLiveness retient le dernier échange réussi avec chaque pair.
type peerLiveness struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (p *peerLiveness) mark(name string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]time.Time{}
	}
	p.seen[strings.ToLower(name)] = at
}

func (p *peerLiveness) alive(name string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, ok := p.seen[strings.ToLower(name)]
	return ok && now.Sub(at) <= peerAliveFor
}

// ruleReports dédoublonne les déclenchements remontés à l'Admin.
type ruleReports struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// first dit si ce déclenchement est le premier de la règle dans la fenêtre, et le retient.
func (r *ruleReports) first(ruleID string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last = map[string]time.Time{}
	}
	if at, ok := r.last[ruleID]; ok && now.Sub(at) < ruleReportWindow {
		return false
	}
	r.last[ruleID] = now
	return true
}

// groupMemberOrder : les membres du groupe dans l'ordre où l'exécutant est choisi. Ordre de la fiche (identifiant du
// nœud) ; à défaut de fiche, ordre de la liste des membres du portail.
func (s *Server) groupMemberOrder() []string {
	if card, ok := s.groupCard.get(); ok && len(card.Members) > 0 {
		ms := append([]edgews.CardMember(nil), card.Members...)
		sort.Slice(ms, func(i, j int) bool { return ms[i].ID < ms[j].ID })
		names := make([]string, 0, len(ms))
		for _, m := range ms {
			names = append(names, m.Name)
		}
		return names
	}
	if s.portal != nil {
		if _, _, members, ok := s.portal.HAGroupInfo(); ok {
			return members
		}
	}
	return nil
}

// groupExecutor rend le premier membre vu vivant. self=true : c'est ce membre (aussi quand il est seul, ou quand le
// groupe n'est pas connu).
func (s *Server) groupExecutor(now time.Time) (exec proxy.PeerInfo, self bool) {
	me := s.cfg.Identity.NodeName
	for _, name := range s.groupMemberOrder() {
		if strings.EqualFold(name, me) {
			return proxy.PeerInfo{}, true
		}
		if s.peers == nil || !s.peerSeen.alive(name, now) {
			continue
		}
		for _, p := range s.peers.All() {
			if strings.EqualFold(p.Name, name) {
				return p, false
			}
		}
	}
	return proxy.PeerInfo{}, true
}

// reportRuleFired remonte un déclenchement à l'Admin, sauf s'il n'est qu'un doublon d'un déclenchement de notification
// déjà remonté pour la même règle.
func (s *Server) reportRuleFired(p edgews.RuleFiredPayload) {
	if isNotifyFiring(p) && !s.ruleReports.first(p.RuleID, time.Now()) {
		s.log.Debug("rulesengine: déclenchement déjà remonté par le groupe", "rule", p.RuleID, "node", p.NodeName)
		return
	}
	if s.ruleReportHook != nil {
		s.ruleReportHook(p)
	}
	if s.wsHub == nil {
		return
	}
	if msg, err := edgews.NewMessage(0, edgews.TypeRuleFired, p); err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}

func isNotifyFiring(p edgews.RuleFiredPayload) bool {
	return p.ActionType == "notify" && p.CondResult && p.ActionTaken && !p.Silenced
}

// forwardRuleFired confie un déclenchement de notification à l'exécutant du groupe. Faux : c'est ce membre l'exécutant,
// ou l'exécutant n'a pas répondu — à lui de le remonter.
func (s *Server) forwardRuleFired(p edgews.RuleFiredPayload) bool {
	exec, self := s.groupExecutor(time.Now())
	if self {
		return false
	}
	_, key, ok := s.haAgentPeers()
	if !ok {
		return false
	}
	sealed, err := sealGroupJSON(p, key, groupRuleFiredLabel)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exec.Endpoint+groupRuleFiredPath, bytes.NewReader(sealed))
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+exec.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode/100 == 2
}

// POST /internal/v1/group/rule-fired : un membre du groupe confie à l'exécutant un déclenchement de notification qu'il a
// vu. Le corps est chiffré par la clé du groupe.
func (s *Server) handleGroupRuleFired(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		http.NotFound(w, r)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "corps illisible", http.StatusBadRequest)
		return
	}
	var p edgews.RuleFiredPayload
	if err := openGroupJSON(data, key, groupRuleFiredLabel, &p); err != nil || p.RuleID == "" || !isNotifyFiring(p) {
		http.Error(w, "déclenchement refusé", http.StatusBadRequest)
		return
	}
	s.reportRuleFired(p)
	w.WriteHeader(http.StatusNoContent)
}
