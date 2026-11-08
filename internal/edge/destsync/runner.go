// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package destsync

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"time"
)

// Inventory est le résultat d'un passage d'une source : l'état complet de ce qu'elle voit, pas un journal. Un passage en
// erreur ne porte aucune machine et l'Admin n'en tire rien (une panne d'API ne retire jamais une destination).
type Inventory struct {
	SourceID string    `json:"source_id"`
	Type     string    `json:"type"`
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
	Machines []Machine `json:"machines"`
}

const (
	listTimeout = 2 * time.Minute
	// maxMachines borne un inventaire : au-delà, la source est refusée plutôt que tronquée (un inventaire tronqué ferait
	// croire à la disparition des machines manquantes).
	maxMachines = 5000
)

// Runner rejoue les sources configurées et remet chaque inventaire à report. Il ne fait rien tant qu'il n'est pas actif :
// seul le membre qui héberge le portail interroge les fournisseurs.
type Runner struct {
	report func(Inventory)
	build  func(typ string, cfg map[string]any) (Source, error)

	mu      sync.Mutex
	ctx     context.Context
	workers map[string]*worker
}

type worker struct {
	cfg     SourceConfig
	cancel  context.CancelFunc
	trigger chan struct{}
}

// NewRunner crée un exécuteur. report est appelé depuis les goroutines des sources : il doit être sûr en concurrence.
func NewRunner(report func(Inventory)) *Runner {
	return &Runner{report: report, build: Build, workers: map[string]*worker{}}
}

// Start lie l'exécuteur au contexte du serveur ; à l'annulation, toutes les sources s'arrêtent.
func (r *Runner) Start(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
	go func() {
		<-ctx.Done()
		r.Apply(nil, false)
	}()
}

// Apply remplace l'ensemble des sources. Une source inchangée n'est pas relancée (elle garde son rythme) ; une source
// modifiée repart aussitôt. inactive : toutes les sources sont arrêtées.
func (r *Runner) Apply(cfgs []SourceConfig, active bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[string]SourceConfig{}
	if active && r.ctx != nil && r.ctx.Err() == nil {
		for _, c := range cfgs {
			if c.Enabled && c.ID != "" {
				want[c.ID] = c
			}
		}
	}
	for id, w := range r.workers {
		if c, ok := want[id]; !ok || !reflect.DeepEqual(c, w.cfg) {
			w.cancel()
			delete(r.workers, id)
		}
	}
	for id, c := range want {
		if _, ok := r.workers[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(r.ctx)
		w := &worker{cfg: c, cancel: cancel, trigger: make(chan struct{}, 1)}
		r.workers[id] = w
		go r.run(ctx, w)
	}
}

// SyncNow demande un passage immédiat. Faux : la source n'est pas active ici.
func (r *Runner) SyncNow(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.workers[id]
	if !ok {
		return false
	}
	select {
	case w.trigger <- struct{}{}:
	default:
	}
	return true
}

// Active retourne les identifiants des sources en cours d'exécution, triés.
func (r *Runner) Active() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.workers))
	for id := range r.workers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (r *Runner) run(ctx context.Context, w *worker) {
	wait := firstPassDelay()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-w.trigger:
		}
		r.pass(ctx, w.cfg)
		every := time.Duration(w.cfg.Interval()) * time.Second
		wait = every + time.Duration(rand.Int63n(int64(every/10)+1)) // gigue : les sources d'un même fournisseur ne partent pas ensemble
	}
}

func (r *Runner) pass(ctx context.Context, c SourceConfig) {
	inv := Inventory{SourceID: c.ID, Type: c.Type, At: time.Now().UTC(), Machines: []Machine{}}
	defer func() {
		if rec := recover(); rec != nil {
			inv = Inventory{SourceID: c.ID, Type: c.Type, At: inv.At, Error: fmt.Sprintf("erreur interne : %v", rec), Machines: []Machine{}}
		}
		if ctx.Err() == nil {
			r.report(inv)
		}
	}()
	src, err := r.build(c.Type, c.Config)
	if err != nil {
		inv.Error = err.Error()
		return
	}
	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	machines, err := src.List(lctx)
	if err != nil {
		inv.Error = err.Error()
		return
	}
	machines, err = cleanMachines(machines)
	if err != nil {
		inv.Error = err.Error()
		return
	}
	inv.OK, inv.Machines = true, machines
}

// cleanMachines normalise un inventaire : port par défaut, identifiants uniques, ordre stable.
func cleanMachines(in []Machine) ([]Machine, error) {
	if len(in) > maxMachines {
		return nil, fmt.Errorf("inventaire trop grand (%d machines, maximum %d) : restreindre la source par pool ou par étiquette", len(in), maxMachines)
	}
	seen := make(map[string]bool, len(in))
	out := make([]Machine, 0, len(in))
	for _, m := range in {
		if m.ExternalID == "" || seen[m.ExternalID] {
			continue
		}
		seen[m.ExternalID] = true
		if m.Port <= 0 {
			m.Port = 22
		}
		if m.Name == "" {
			m.Name = m.ExternalID
		}
		m.Tags = normalizeTags(m.Tags...)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExternalID < out[j].ExternalID })
	return out, nil
}

// Test construit une source et la lit une fois, sans rien retenir : c'est ce que fait le bouton « Tester » de l'Admin,
// depuis la passerelle, qui est l'endroit d'où le fournisseur doit être joignable.
func Test(ctx context.Context, typ string, cfg map[string]any) ([]Machine, error) {
	man, ok := ManifestOf(typ)
	if !ok {
		return nil, fmt.Errorf("type de source inconnu : %s", typ)
	}
	if err := man.Validate(cfg); err != nil {
		return nil, err
	}
	src, err := Build(typ, cfg)
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	machines, err := src.List(lctx)
	if err != nil {
		return nil, err
	}
	return cleanMachines(machines)
}

// firstPassDelay : le premier passage suit de près la configuration, avec une gigue pour que plusieurs passerelles
// redémarrées ensemble n'interrogent pas le fournisseur au même instant. Les tests le raccourcissent.
var firstPassDelay = func() time.Duration { return time.Duration(1+rand.Intn(5)) * time.Second }
