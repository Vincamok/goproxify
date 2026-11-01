// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Application des accès aux services qui ne portent pas de proxy (logs, certificats, alertes, métriques ; ADR 0022,
// section 5) : le périmètre d'un accès est résolu en ensemble d'hôtes — ceux des proxys qu'il couvre et les domaines
// qu'il désigne — puis les lignes, certificats et événements dont l'hôte est connu sont filtrés. Ce qui n'a pas d'hôte
// (analyses, événements sans domaine) n'est visible que d'un accès sans critère.

// Caller est le compte qui appelle, avec les accès de ses équipes chargés une fois.
type Caller struct {
	UserID   string
	Role     string
	Accesses []TeamAccess
}

// IsAdmin : l'administrateur voit toute la plateforme.
func (c *Caller) IsAdmin() bool { return c != nil && IsAdminRole(c.Role) }

// Filter rend le périmètre à appliquer pour la permission.
func (c *Caller) Filter(permission string) Filter {
	if c == nil || c.IsAdmin() {
		return Filter{all: true}
	}
	return FilterFor(c.Accesses, permission)
}

type callerKey struct{}

// WithCaller range l'appelant dans le contexte de la requête.
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom rend l'appelant posé par la garde, ou nil : sans garde (appel direct, test), rien n'est restreint.
func CallerFrom(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}

// LoadCaller charge le rôle et les accès du compte.
func LoadCaller(ctx context.Context, db *sql.DB, userID string) (*Caller, error) {
	c := &Caller{UserID: userID, Role: UserRole(ctx, db, userID)}
	if IsAdminRole(c.Role) {
		return c, nil
	}
	var err error
	c.Accesses, err = UserAccesses(ctx, db, userID)
	return c, err
}

// GatePermission rend la permission qu'exige une requête, et false si la garde ne la concerne pas (elle passe alors
// telle quelle à l'enveloppe suivante).
type GatePermission func(r *http.Request) (permission string, gated bool)

// Gate refuse à un compte sans accès la requête qu'il n'a pas le droit de faire, et range l'appelant dans le contexte
// pour que le handler filtre ses données. Un administrateur passe toujours.
func Gate(db *sql.DB, resolve GatePermission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			caller, err := LoadCaller(r.Context(), db, userID)
			if err != nil {
				http.Error(w, "accès insuffisant", http.StatusForbidden)
				return
			}
			r = r.WithContext(WithCaller(r.Context(), caller))
			if caller.IsAdmin() {
				next.ServeHTTP(w, r)
				return
			}
			permission, gated := resolve(r)
			if gated && caller.Filter(permission).None() {
				http.Error(w, "accès insuffisant: "+permission, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var routeSource = struct {
	mu      sync.Mutex
	fn      func(context.Context) ([]router.Route, error)
	cached  []router.Route
	fetched time.Time
}{}

const routeSourceTTL = 10 * time.Second

// SetRouteSource indique où lire les proxys configurés pour résoudre un périmètre en hôtes.
func SetRouteSource(fn func(context.Context) ([]router.Route, error)) {
	routeSource.mu.Lock()
	defer routeSource.mu.Unlock()
	routeSource.fn, routeSource.cached = fn, nil
}

func currentRoutes(ctx context.Context) []router.Route {
	routeSource.mu.Lock()
	defer routeSource.mu.Unlock()
	if routeSource.fn == nil {
		return nil
	}
	if routeSource.cached == nil || time.Since(routeSource.fetched) > routeSourceTTL {
		if routes, err := routeSource.fn(ctx); err == nil {
			routeSource.cached, routeSource.fetched = routes, time.Now()
		}
	}
	return routeSource.cached
}

// Visibility dit quels hôtes un appelant voit pour une permission.
type Visibility struct {
	filter   Filter
	covered  map[string]bool
	patterns []string
}

// VisibilityFor résout le périmètre de l'appelant pour la permission en hôtes visibles.
func VisibilityFor(ctx context.Context, c *Caller, permission string) Visibility {
	return NewVisibility(c.Filter(permission), currentRoutes(ctx), currentGroups())
}

// NewVisibility résout un filtre en hôtes : ceux des proxys qu'il couvre, et ses domaines quand un accès ne désigne
// que des domaines.
func NewVisibility(f Filter, routes []router.Route, groups GroupCatalog) Visibility {
	v := Visibility{filter: f, covered: map[string]bool{}}
	if f.all {
		return v
	}
	for _, p := range f.perimeters {
		if p.Domain != "" && p.Proxy == "" && p.Backend == "" && p.Group.empty() && len(p.Labels) == 0 {
			v.patterns = append(v.patterns, strings.ToLower(p.Domain))
		}
	}
	for i := range routes {
		if !f.AllowsRoute(&routes[i], groups) {
			continue
		}
		if routes[i].Host != "" {
			v.covered[strings.ToLower(routes[i].Host)] = true
		}
		for _, a := range routes[i].Aliases {
			v.covered[strings.ToLower(a)] = true
		}
	}
	return v
}

// All : aucun critère, tout est visible (y compris ce qui n'a pas d'hôte).
func (v Visibility) All() bool { return v.filter.all }

// None : rien n'est visible.
func (v Visibility) None() bool { return v.filter.None() }

// Host dit si l'hôte est visible.
func (v Visibility) Host(host string) bool {
	if v.filter.all {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if v.covered[host] {
		return true
	}
	return slices.ContainsFunc(v.patterns, func(p string) bool { return hostMatchesDomainScope(p, host) })
}

// Hosts rend les hôtes connus qui sont visibles (triés), sans les domaines à motif.
func (v Visibility) Hosts() []string {
	out := make([]string, 0, len(v.covered))
	for h := range v.covered {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Patterns rend les motifs de domaine qu'un accès désigne seul.
func (v Visibility) Patterns() []string { return v.patterns }

// CertName dit si un certificat est visible : son nom (ou son nom sans « *. ») couvre un hôte visible, ou un motif de
// domaine visible le couvre.
func (v Visibility) CertName(name string) bool {
	if v.filter.all {
		return true
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if v.Host(name) || v.Host(strings.TrimPrefix(name, "*.")) {
		return true
	}
	for h := range v.covered {
		if router.HostCoveredByPattern(h, name) {
			return true
		}
	}
	return slices.ContainsFunc(v.patterns, func(p string) bool { return p == name })
}

// Pattern dit si un motif de domaine (celui d'une règle d'alerte) est contenu dans ce que l'appelant voit : un motif
// qu'il désigne lui-même, ou couvert par l'un d'eux.
func (v Visibility) Pattern(glob string) bool {
	if v.filter.all {
		return true
	}
	glob = strings.ToLower(strings.TrimSpace(glob))
	if glob == "" {
		return false
	}
	return slices.ContainsFunc(v.patterns, func(p string) bool {
		return p == glob || (strings.HasPrefix(p, "*.") && strings.HasSuffix(glob, p[1:]))
	}) || (!strings.Contains(glob, "*") && v.Host(glob))
}
