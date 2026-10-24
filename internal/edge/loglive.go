// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	// logLiveMaxTTL borne ce qu'une demande peut réclamer : une Admin qui disparaît ne laisse pas la passerelle émettre.
	logLiveMaxTTL = 60 * time.Second
	// logLiveRowsPerSecond : au-delà, les lignes sont sautées (l'écran Live ne sert pas à tout lire, la recherche le fait).
	logLiveRowsPerSecond = 500
	logLiveBatch         = 100
)

// logLives suit les vues Live ouvertes par chaque connexion Admin.
type logLives struct {
	mu   sync.Mutex
	subs map[string]*liveSub
}

type liveSub struct {
	deadline time.Time
	cancel   context.CancelFunc
}

// handleLogLive ouvre ou prolonge l'envoi des nouvelles lignes vers l'Admin connID. L'Admin n'en reçoit pas d'autres :
// quand il ne veut des accès ordinaires que sur demande, c'est ainsi que le mode Live les voit passer.
func (s *Server) handleLogLive(connID string, raw json.RawMessage) error {
	if s.logStore == nil {
		return nil
	}
	var p edgews.LogLivePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	ttl := min(time.Duration(p.TTLSec)*time.Second, logLiveMaxTTL)
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	l := &s.logLive
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.subs == nil {
		l.subs = map[string]*liveSub{}
	}
	if sub, ok := l.subs[connID]; ok {
		sub.deadline = time.Now().Add(ttl)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	sub := &liveSub{deadline: time.Now().Add(ttl), cancel: cancel}
	l.subs[connID] = sub
	go func() {
		s.tailLogs(ctx, connID, sub)
		l.mu.Lock()
		if l.subs[connID] == sub {
			delete(l.subs, connID)
		}
		l.mu.Unlock()
		cancel()
	}()
	return nil
}

func (l *logLives) expired(sub *liveSub) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().After(sub.deadline)
}

// tailLogs envoie les lignes écrites après l'ouverture de la vue, d'un débit borné, jusqu'à l'expiration de la demande.
func (s *Server) tailLogs(ctx context.Context, connID string, sub *liveSub) {
	pos := map[logstore.Kind]int64{}
	for _, k := range logStreamKinds {
		pos[k.kind] = s.logStore.LastID(k.kind)
	}
	budget, window := logLiveRowsPerSecond, time.Now()
	for {
		changed := s.logStore.Changed()
		if s.logLive.expired(sub) || !s.wsHub.HasAdmin(connID) {
			return
		}
		if time.Since(window) >= time.Second {
			budget, window = logLiveRowsPerSecond, time.Now()
		}
		dropped := false
		var entries []edgews.LogEntryPayload
		for _, k := range logStreamKinds {
			last := s.logStore.LastID(k.kind)
			if last <= pos[k.kind] {
				continue
			}
			if budget <= 0 {
				pos[k.kind], dropped = last, true
				continue
			}
			rows, err := s.logStore.ReadAfter(k.kind, pos[k.kind], min(logLiveBatch, budget))
			if err != nil {
				s.log.Warn("logs: lecture pour la vue Live échouée", "err", err)
				continue
			}
			for _, r := range rows {
				entries = append(entries, shipPayload(edgelog.ShipEntryFromRow(r, k.kind, s.cfg.Identity.NodeName)))
			}
			if len(rows) > 0 {
				pos[k.kind] = rows[len(rows)-1].ID
				budget -= len(rows)
			}
		}
		if len(entries) > 0 || dropped {
			msg, err := edgews.NewMessage(0, edgews.TypeLogLiveRows, edgews.LogLiveRowsPayload{Entries: entries, Dropped: dropped})
			if err != nil || s.wsHub.SendToAdmin(connID, msg) != nil {
				return
			}
			if len(entries) >= logLiveBatch {
				continue // il en reste peut-être : relire sans attendre
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(time.Second):
		}
	}
}

func (l *logLives) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, sub := range l.subs {
		sub.cancel()
		delete(l.subs, id)
	}
}
