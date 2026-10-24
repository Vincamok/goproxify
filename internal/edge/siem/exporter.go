// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Source est la base de logs que l'exporteur lit.
type Source interface {
	ReadAfter(kind logstore.Kind, after int64, limit int) ([]logstore.Row, error)
	LastID(kind logstore.Kind) int64
	PositionAt(kind logstore.Kind, t time.Time) int64
	Changed() <-chan struct{}
}

// State garde les positions de lecture de chaque destination (identifiant → type de logs → position) : elles
// survivent à un redémarrage, sans l'Admin.
type State interface {
	Load() (map[string]map[string]int64, error)
	Save(map[string]map[string]int64) error
}

// Options règle l'exporteur.
type Options struct {
	Node   string
	Source Source
	State  State
	// Retention rend la durée de conservation d'un type de logs : un retard qui s'en approche est « à risque ».
	Retention func(kind logstore.Kind) time.Duration
	Log       *slog.Logger
	// NewSender (tests) remplace la fabrique de transports.
	NewSender func(Destination) (Sender, error)
	Now       func() time.Time
	BatchSize int
	// MinBackoff et MaxBackoff encadrent l'attente entre deux essais après un échec.
	MinBackoff, MaxBackoff time.Duration
}

// Manager fait tourner un exporteur par destination configurée.
type Manager struct {
	opts Options

	applyMu  sync.Mutex // sérialise Apply
	mu       sync.Mutex
	workers  map[string]*worker
	pos      map[string]map[string]int64
	dirty    bool
	lastSave time.Time
	closed   bool
}

// New crée l'exporteur ; il n'envoie rien tant qu'une configuration activée n'est pas appliquée.
func New(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = time.Minute
	}
	if opts.NewSender == nil {
		opts.NewSender = NewSender
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	m := &Manager{opts: opts, workers: map[string]*worker{}, pos: map[string]map[string]int64{}}
	if opts.State != nil {
		if p, err := opts.State.Load(); err != nil {
			opts.Log.Warn("siem: positions illisibles, les destinations repartent de maintenant", "err", err)
		} else if p != nil {
			m.pos = p
		}
	}
	return m
}

var allKinds = []logstore.Kind{logstore.KindAccess, logstore.KindSystem}

func kindOf(name string) logstore.Kind { return logstore.Kind(name) }

type worker struct {
	dest   Destination
	raw    []byte
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	state     string
	lastErr   string
	lastErrAt time.Time
	sent      int64
	lastOK    time.Time
}

// Apply met l'exporteur en accord avec la configuration : les destinations retirées ou modifiées sont arrêtées, les
// nouvelles ou modifiées démarrées. Une destination désactivée ou retirée perd sa position.
func (m *Manager) Apply(cfg Config) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	want := map[string]Destination{}
	if cfg.Enabled {
		for _, d := range cfg.Destinations {
			want[d.ID] = d
		}
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	var stopped []*worker
	for id, w := range m.workers {
		raw, _ := json.Marshal(want[id])
		if _, ok := want[id]; !ok || !bytes.Equal(raw, w.raw) {
			stopped = append(stopped, w)
			delete(m.workers, id)
		}
	}
	m.mu.Unlock()
	// Un worker lit ses positions sous m.mu : on l'attend hors du verrou.
	for _, w := range stopped {
		w.cancel()
		<-w.done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for id := range m.pos {
		if _, ok := want[id]; !ok {
			delete(m.pos, id)
			m.dirty = true
		}
	}
	for id, d := range want {
		if _, ok := m.workers[id]; ok {
			continue
		}
		m.startLocked(d)
	}
	m.persistLocked(true)
}

func (m *Manager) startLocked(d Destination) {
	positions := m.pos[d.ID]
	if positions == nil {
		positions = map[string]int64{}
		m.pos[d.ID] = positions
		m.dirty = true
	}
	for _, k := range allKinds {
		if !d.Wants(string(k)) {
			continue
		}
		if _, ok := positions[string(k)]; ok {
			continue
		}
		if d.BackfillHours > 0 {
			positions[string(k)] = m.opts.Source.PositionAt(k, m.opts.Now().Add(-time.Duration(d.BackfillHours)*time.Hour))
		} else {
			positions[string(k)] = m.opts.Source.LastID(k)
		}
		m.dirty = true
	}
	raw, _ := json.Marshal(d)
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{dest: d, raw: raw, cancel: cancel, done: make(chan struct{}), state: "starting"}
	m.workers[d.ID] = w
	go func() {
		defer close(w.done)
		m.run(ctx, w)
	}()
}

// Close arrête tous les exporteurs et enregistre les positions.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	workers := m.workers
	m.workers = map[string]*worker{}
	m.mu.Unlock()
	for _, w := range workers {
		w.cancel()
		<-w.done
	}
	m.mu.Lock()
	m.persistLocked(true)
	m.mu.Unlock()
}

func (m *Manager) position(id, kind string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pos[id][kind]
}

// advance enregistre la position d'une destination ; elle est écrite sur disque au plus toutes les deux secondes.
func (m *Manager) advance(id, kind string, pos int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pos[id] == nil {
		return
	}
	m.pos[id][kind] = pos
	m.dirty = true
	m.persistLocked(false)
}

func (m *Manager) persistLocked(force bool) {
	if !m.dirty || m.opts.State == nil {
		return
	}
	if !force && m.opts.Now().Sub(m.lastSave) < 2*time.Second {
		return
	}
	if err := m.opts.State.Save(m.pos); err != nil {
		m.opts.Log.Warn("siem: positions non enregistrées", "err", err)
		return
	}
	m.dirty, m.lastSave = false, m.opts.Now()
}

func levelOK(d Destination, level string) bool {
	min := LevelRank("info")
	if d.MinLevel != "" {
		min = LevelRank(d.MinLevel)
	}
	return LevelRank(level) >= min
}

func flagged(r logstore.Row) bool { return len(r.WAFMatches) > 0 || r.ThreatSignal != "" }

func (m *Manager) run(ctx context.Context, w *worker) {
	d := w.dest
	var sender Sender
	defer func() {
		if sender != nil {
			sender.Close()
		}
		w.setState("stopped", "")
	}()
	backoff := m.opts.MinBackoff
	for {
		changed := m.opts.Source.Changed()
		progressed, failed := false, false
		for _, k := range allKinds {
			if !d.Wants(string(k)) {
				continue
			}
			pos := m.position(d.ID, string(k))
			rows, err := m.opts.Source.ReadAfter(k, pos, m.opts.BatchSize)
			if err != nil {
				w.setState("retrying", "lecture de la base : "+err.Error())
				continue
			}
			if len(rows) == 0 {
				// Un curseur au-delà de tout ce que la base a attribué : elle a été remplacée (état restauré sans le
				// dossier des logs). On repart de son début, au risque de quelques doublons que l'identifiant permet
				// d'écarter, plutôt que de sauter ses premières lignes.
				if pos > m.opts.Source.LastID(k) {
					m.opts.Log.Warn("siem: la base de logs est plus récente que le curseur, la destination repart du début", "destination", d.Name, "type", string(k))
					m.advance(d.ID, string(k), 0)
					progressed = true
				}
				continue
			}
			var recs []Record
			for _, r := range rows {
				if !levelOK(d, r.Level) || (d.SecurityOnly && k == logstore.KindAccess && !flagged(r)) {
					continue
				}
				recs = append(recs, Record{Node: m.opts.Node, Kind: string(k), Row: r})
			}
			if len(recs) > 0 {
				if sender == nil {
					s, err := m.opts.NewSender(d)
					if err != nil {
						w.setState("retrying", err.Error())
						if !sleep(ctx, backoff) {
							return
						}
						backoff = min(backoff*2, m.opts.MaxBackoff)
						failed = true
						continue
					}
					sender = s
				}
				if err := sender.Send(ctx, recs); err != nil {
					if ctx.Err() != nil {
						return
					}
					w.setState("retrying", err.Error())
					m.opts.Log.Warn("siem: livraison échouée, nouvel essai", "destination", d.Name, "err", err)
					if !sleep(ctx, backoff) {
						return
					}
					backoff = min(backoff*2, m.opts.MaxBackoff)
					failed = true
					continue
				}
				w.markSent(int64(len(recs)), m.opts.Now())
			}
			backoff = m.opts.MinBackoff
			w.setState("ok", "")
			m.advance(d.ID, string(k), rows[len(rows)-1].ID)
			progressed = true
		}
		if progressed || failed {
			continue
		}
		m.mu.Lock()
		m.persistLocked(true)
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(5 * time.Second):
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (w *worker) setState(state, err string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state = state
	if err != "" {
		w.lastErr, w.lastErrAt = err, time.Now()
	} else if state == "ok" {
		w.lastErr = ""
	}
}

func (w *worker) markSent(n int64, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sent += n
	w.lastOK = at
}
