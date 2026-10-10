// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// tableData est le contenu de la table à un instant donné. Replace en construit un neuf et le publie d'un
// coup : une sync.Map ne se copie pas, et un lecteur ne doit jamais voir un mélange de l'ancien et du nouveau.
type tableData struct {
	routes sync.Map // key: route.ID → *Route
	byHost sync.Map // key: host      → *Route  (HTTP uniquement)
	byPort sync.Map // key: port(int) → *Route  (TCP/UDP uniquement)
	count  atomic.Int64
}

// Table est la table de routage de la passerelle. Les lectures sont thread-safe et sans verrou ; les écritures
// (Upsert, Delete, Replace) sont sérialisées entre elles, ce qui évite qu'une mise à jour tombe dans le contenu
// que Replace vient de remplacer. La valeur zéro est utilisable.
type Table struct {
	data atomic.Pointer[tableData]
	mu   sync.Mutex // sérialise les écritures

	onChange atomic.Pointer[func()] // appelé après chaque modification de la table
}

// d retourne le contenu courant, créé au premier usage.
func (t *Table) d() *tableData {
	if d := t.data.Load(); d != nil {
		return d
	}
	t.data.CompareAndSwap(nil, &tableData{})
	return t.data.Load()
}

// SetOnChange enregistre une fonction appelée après chaque Upsert, Delete ou Replace (rapprochement des
// écouteurs TCP/UDP avec la table). Elle doit être rapide et ne pas bloquer.
func (t *Table) SetOnChange(fn func()) {
	if fn == nil {
		t.onChange.Store(nil)
		return
	}
	t.onChange.Store(&fn)
}

func (t *Table) changed() {
	if fn := t.onChange.Load(); fn != nil {
		(*fn)()
	}
}

func hostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

// hostKeys liste les clés d'hôte (host et alias) d'une route.
func hostKeys(r *Route) []string {
	keys := make([]string, 0, 1+len(r.Aliases))
	if r.Host != "" {
		keys = append(keys, hostKey(r.Host))
	}
	for _, a := range r.Aliases {
		if a != "" {
			keys = append(keys, hostKey(a))
		}
	}
	return keys
}

// upsertLocked écrit la route dans d. Les nouvelles clés sont posées avant le retrait de celles que l'ancienne
// version possédait et que la nouvelle n'a plus : un hôte conservé n'est jamais absent de la table, même un instant.
func (d *tableData) upsertLocked(r *Route) {
	prev, loaded := d.routes.Swap(r.ID, r)
	if !loaded {
		d.count.Add(1)
	}
	kept := map[string]bool{}
	for _, k := range hostKeys(r) {
		kept[k] = true
		d.byHost.Store(k, r)
	}
	if r.ListenPort > 0 {
		d.byPort.Store(r.ListenPort, r)
	}
	if !loaded {
		return
	}
	old := prev.(*Route)
	for _, k := range hostKeys(old) {
		if !kept[k] {
			d.byHost.Delete(k)
		}
	}
	if old.ListenPort > 0 && old.ListenPort != r.ListenPort {
		d.byPort.Delete(old.ListenPort)
	}
}

// Upsert ajoute ou remplace une route.
func (t *Table) Upsert(r *Route) {
	t.mu.Lock()
	t.d().upsertLocked(r)
	t.mu.Unlock()
	t.changed()
}

// Delete supprime une route par son ID.
func (t *Table) Delete(id string) bool {
	t.mu.Lock()
	d := t.d()
	val, loaded := d.routes.LoadAndDelete(id)
	if !loaded {
		t.mu.Unlock()
		return false
	}
	r := val.(*Route)
	for _, k := range hostKeys(r) {
		d.byHost.Delete(k)
	}
	if r.ListenPort > 0 {
		d.byPort.Delete(r.ListenPort)
	}
	d.count.Add(-1)
	t.mu.Unlock()
	t.changed()
	return true
}

// DisableByIDOrHost retire de la table la route correspondant à l'ID ou au host.
// Utilisé par le moteur de règles automatiques (disable_proxy action).
func (t *Table) DisableByIDOrHost(idOrHost string) {
	t.d().routes.Range(func(key, val any) bool {
		r := val.(*Route)
		if r.ID == idOrHost || r.Host == idOrHost {
			t.Delete(r.ID)
		}
		return true
	})
}

// ByHost retourne la route correspondant à un Host header.
// Essaie d'abord un match exact, puis un match wildcard (*.parent.tld).
func (t *Table) ByHost(host string) (*Route, bool) {
	host = hostKey(host)
	if val, ok := t.d().byHost.Load(host); ok {
		return val.(*Route), true
	}
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		if val, ok := t.d().byHost.Load("*" + host[idx:]); ok {
			return val.(*Route), true
		}
	}
	return nil, false
}

// PassthroughRoute retourne une route TLS passthrough pour host si elle existe.
// Contrairement à ByHost, un proxy exact non-passthrough n'empêche pas de trouver
// un wildcard passthrough (ex: deleg-* *.domaine.fr) — requis pour la délégation inter-passerelles.
func (t *Table) PassthroughRoute(host string) (*Route, bool) {
	host = hostKey(host)
	if val, ok := t.d().byHost.Load(host); ok {
		if r := val.(*Route); r.TLSPassthrough {
			return r, true
		}
	}
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		if val, ok := t.d().byHost.Load("*" + host[idx:]); ok {
			if r := val.(*Route); r.TLSPassthrough {
				return r, true
			}
		}
	}
	return nil, false
}

// HostCoveredByPattern indique si host est couvert par un motif exact ou wildcard DNS.
// "*.example.fr" couvre un seul label ("api.example.fr") mais pas "a.b.example.fr"
// — aligné sur ByHost / PassthroughRoute.
func HostCoveredByPattern(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == "" || pattern == "" {
		return false
	}
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.fr"
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			return false
		}
		rest := host[:len(host)-len(suffix)]
		return rest != "" && !strings.Contains(rest, ".")
	}
	return false
}

// ByPort retourne la route TCP/UDP écoutant sur ce port.
func (t *Table) ByPort(port int) (*Route, bool) {
	val, ok := t.d().byPort.Load(port)
	if !ok {
		return nil, false
	}
	return val.(*Route), true
}

// All retourne toutes les routes (snapshot).
func (t *Table) All() []*Route {
	d := t.d()
	routes := make([]*Route, 0, d.count.Load())
	d.routes.Range(func(_, val any) bool {
		routes = append(routes, val.(*Route))
		return true
	})
	return routes
}

// Len retourne le nombre de routes.
func (t *Table) Len() int64 { return t.d().count.Load() }

// Replace remplace toute la table atomiquement (utilisé lors du chargement du cache).
// En cas d'erreur de validation, la table courante n'est pas touchée (revue P1 #11).
func (t *Table) Replace(routes []*Route) error {
	for _, r := range routes {
		if r == nil || r.ID == "" {
			return fmt.Errorf("route sans ID ignorée")
		}
	}
	next := &tableData{}
	for _, r := range routes {
		next.upsertLocked(r)
	}
	t.mu.Lock()
	t.data.Store(next)
	t.mu.Unlock()
	t.changed()
	return nil
}

// ByID retourne la route d'identifiant id.
func (t *Table) ByID(id string) (*Route, bool) {
	val, ok := t.d().routes.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*Route), true
}
