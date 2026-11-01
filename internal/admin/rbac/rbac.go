// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package rbac implémente le contrôle d'accès basé sur les rôles pour l'Admin.
//
// Hiérarchie des rôles plateforme :
//
//	superadmin : accès total, protégé (non supprimable), premier compte créé
//	admin      : toute la plateforme ; aucun grant ne le restreint ni ne l'étend
//	user       : uniquement ce que lui donnent les accès de ses équipes (team_accesses) ; sans équipe, rien
//
// Les droits sur les ressources ne se portent que par les équipes (ADR 0021). Les capacités
// (permissions.go) s'obtiennent aussi par une équipe, jamais par le compte.
//
// Un accès d'équipe est un périmètre (perimeter.go) et un niveau par service (team_access.go, catalog.go) ; le
// moteur (engine.go) répond Can et Scope. Les Scope ci-dessous ne servent plus qu'aux jetons des passerelles
// (token_scopes : domain, server, proxy, edge).
package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Access modes pour un grant.
const (
	AccessRead  = "read"
	AccessWrite = "write"
)

// Scope représente un périmètre d'accès (tokens passerelle / match route).
type Scope struct {
	Type  string // "domain" | "server" | "proxy" | "edge"
	Value string
}

// Grant est l'accès d'une équipe tel que les contrôles de proxy le reçoivent (ADR 0022).
type Grant = TeamAccess

// match retourne true si la route correspond à ce scope.
func (s Scope) match(route *router.Route) bool {
	switch s.Type {
	case "proxy":
		return s.Value == route.ID
	case "domain":
		if hostMatchesDomainScope(s.Value, route.Host) {
			return true
		}
		for _, a := range route.Aliases {
			if hostMatchesDomainScope(s.Value, a) {
				return true
			}
		}
		return false
	case "server":
		for _, b := range route.Backends {
			if ok, _ := path.Match(s.Value, b.URL); ok {
				return true
			}
		}
	case "edge":
		// Un scope edge donne accès à toutes les routes (push global vers toutes les passerelles).
		// La restriction de visibilité passerelle se fait au niveau de la nav, pas des routes.
		return true
	}
	return false
}

// hostMatchesDomainScope aligne HostCoveredByPattern (wildcard DNS 1 label).
// path.Match n'est utilisé que pour les motifs non-wildcard DNS (ex. "api.*.fr").
func hostMatchesDomainScope(pattern, host string) bool {
	if router.HostCoveredByPattern(host, pattern) {
		return true
	}
	p := strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(p, "*.") {
		return false
	}
	ok, _ := path.Match(p, strings.ToLower(host))
	return ok
}

// MatchRoute retourne true si au moins un scope correspond à la route.
func MatchRoute(scopes []Scope, route *router.Route) bool {
	for _, s := range scopes {
		if s.match(route) {
			return true
		}
	}
	return false
}

// RouteAllowedByToken indique si une route est dans le périmètre d'un token passerelle.
// Même sémantique que FilterRoutesByScopes : admin sans scope → tout ; sinon match.
// Streams L4 (tcp/udp) : pas de domaine DNS — hors périmètre token_scopes domain.
func RouteAllowedByToken(role string, scopes []Scope, route *router.Route) bool {
	if route == nil {
		return false
	}
	if routeIsL4(route) {
		return true
	}
	if IsSuperAdminRole(role) || (IsAdminRole(role) && len(scopes) == 0) {
		return true
	}
	if len(scopes) == 0 {
		return false
	}
	return MatchRoute(scopes, route)
}

// FilterRoutesByScopes retourne les routes accessibles selon le rôle et les scopes.
func FilterRoutesByScopes(role string, scopes []Scope, routes []router.Route) []router.Route {
	filtered := make([]router.Route, 0, len(routes))
	for i := range routes {
		if RouteAllowedByToken(role, scopes, &routes[i]) {
			filtered = append(filtered, routes[i])
		}
	}
	return filtered
}

// ResolveEdgeToken résout un token passerelle par UUID ou node_name.
// Préfère l'ID exact, puis un token avec endpoint, puis le plus récent.
// Sans périmètre (scopes vides) + rôle admin → accès à tous les domaines.
func ResolveEdgeToken(ctx context.Context, db *sql.DB, ref string) (tokenID, rbacRole string) {
	acc := ResolveEdgeAccess(ctx, db, ref)
	return acc.TokenID, acc.Role
}

// EdgeAccess est le rôle + scopes effectifs pour une passerelle (push / UI).
type EdgeAccess struct {
	TokenID string
	Role    string
	Scopes  []Scope
}

// ResolveEdgeAccess résout le meilleur token passerelle pour une référence (uuid ou node_name).
func ResolveEdgeAccess(ctx context.Context, db *sql.DB, ref string) EdgeAccess {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return EdgeAccess{}
	}
	var id, role string
	err := db.QueryRowContext(ctx, `
		SELECT t.id, COALESCE(t.rbac_role,'admin')
		FROM tokens t
		WHERE t.role='edge' AND t.revoked=0
		  AND (t.expires_at IS NULL OR t.expires_at > CURRENT_TIMESTAMP)
		  AND (t.id=? OR t.node_name=?)
		ORDER BY
		  CASE WHEN t.id=? THEN 0 ELSE 1 END,
		  CASE WHEN COALESCE(t.node_endpoint,'') != '' THEN 0 ELSE 1 END,
		  t.created_at DESC
		LIMIT 1`, ref, ref, ref).Scan(&id, &role)
	if err != nil || id == "" {
		return EdgeAccess{}
	}
	scopes, _ := TokenScopes(ctx, db, id)
	return EdgeAccess{TokenID: id, Role: role, Scopes: scopes}
}

// LoadEdgeAccess charge le rôle et les scopes du token indiqué.
// Scopes vides + admin = tous les domaines (pas de bascule vers un autre token).
func LoadEdgeAccess(ctx context.Context, db *sql.DB, tokenID, nodeName string) EdgeAccess {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		if nodeName = strings.TrimSpace(nodeName); nodeName != "" {
			return ResolveEdgeAccess(ctx, db, nodeName)
		}
		return EdgeAccess{}
	}
	role := "admin"
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(rbac_role,'admin') FROM tokens WHERE id=?`, tokenID).Scan(&role)
	scopes, _ := TokenScopes(ctx, db, tokenID)
	return EdgeAccess{TokenID: tokenID, Role: role, Scopes: scopes}
}

// ShouldReceiveCert indique si une passerelle doit recevoir le certificat nommé certName
// (ex: "*.dankdown.fr" ou "api.example.fr").
// Même sémantique que les routes : admin sans périmètre → tout ; sinon match domaine/edge.
func ShouldReceiveCert(role string, scopes []Scope, certName string) bool {
	if IsSuperAdminRole(role) || (IsAdminRole(role) && len(scopes) == 0) {
		return true
	}
	if len(scopes) == 0 {
		return false
	}
	return MatchCertName(scopes, certName)
}

// MatchCertName retourne true si au moins un scope couvre le nom de certificat.
func MatchCertName(scopes []Scope, certName string) bool {
	certName = strings.TrimSpace(certName)
	if certName == "" {
		return false
	}
	candidates := []string{certName}
	if strings.HasPrefix(certName, "*.") {
		candidates = append(candidates, certName[2:])
	} else {
		candidates = append(candidates, "*."+certName)
	}
	for _, s := range scopes {
		switch s.Type {
		case "edge":
			// Comme pour les routes : un scope edge donne accès global aux ressources poussées.
			return true
		case "domain":
			for _, c := range candidates {
				if ok, _ := path.Match(s.Value, c); ok {
					return true
				}
			}
			// Scope "*.dankdown.fr" vs cert name exact stocké sans wildcard
			if ok, _ := path.Match(s.Value, certName); ok {
				return true
			}
		}
	}
	return false
}

// --- Fonctions de rôle ---

// IsSuperAdminRole retourne true pour le rôle superadmin.
func IsSuperAdminRole(role string) bool { return role == "superadmin" }

// IsAdminRole retourne true pour admin et superadmin.
func IsAdminRole(role string) bool { return role == "admin" || role == "superadmin" }

// UserRole retourne le rôle global de l'utilisateur.
func UserRole(ctx context.Context, db *sql.DB, userID string) string {
	var role string
	_ = db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, userID).Scan(&role)
	return role
}

// IsSuperAdmin retourne true si l'utilisateur est superadmin.
func IsSuperAdmin(ctx context.Context, db *sql.DB, userID string) bool {
	return IsSuperAdminRole(UserRole(ctx, db, userID))
}

// IsAdmin retourne true si l'utilisateur est admin ou superadmin.
func IsAdmin(ctx context.Context, db *sql.DB, userID string) bool {
	return IsAdminRole(UserRole(ctx, db, userID))
}

// --- Accès utilisateur ---

// UserEffectiveGrants rend les accès des équipes du compte. Un administrateur n'est jamais jugé sur eux : il voit toute
// la plateforme.
func UserEffectiveGrants(ctx context.Context, db *sql.DB, userID string) ([]Grant, error) {
	return UserAccesses(ctx, db, userID)
}

// --- Vérifications d'accès ---

// defaultGroups sert aux contrôles qui n'ont pas de catalogue de groupes sous la main : il est posé au démarrage.
var defaultGroups = struct {
	mu      sync.Mutex
	source  ArchitectureGroups
	set     bool
	cached  GroupCatalog
	fetched time.Time
}{}

const groupCatalogTTL = 2 * time.Second

// SetGroupSource indique d'où lire les groupes de passerelles pour juger un critère de groupe.
func SetGroupSource(source ArchitectureGroups) {
	defaultGroups.mu.Lock()
	defer defaultGroups.mu.Unlock()
	defaultGroups.source, defaultGroups.set, defaultGroups.cached = source, true, nil
}

// currentGroups rend un cliché récent des groupes (relu au plus toutes les deux secondes : une liste de proxys juge
// chaque ligne), ou nil si aucune source n'a été posée.
func currentGroups() GroupCatalog {
	defaultGroups.mu.Lock()
	defer defaultGroups.mu.Unlock()
	if !defaultGroups.set || defaultGroups.source.Store == nil {
		return nil
	}
	if defaultGroups.cached == nil || time.Since(defaultGroups.fetched) > groupCatalogTTL {
		defaultGroups.cached, defaultGroups.fetched = defaultGroups.source.Snapshot(), time.Now()
	}
	return defaultGroups.cached
}

// CanOnRoute dit si les accès d'équipe donnent la permission sur ce proxy (un administrateur peut tout).
func CanOnRoute(role string, accesses []Grant, permission string, route *router.Route) bool {
	return canOnRoute(role, accesses, permission, route)
}

func canOnRoute(role string, accesses []Grant, permission string, route *router.Route) bool {
	if IsAdminRole(role) {
		return true
	}
	return FilterFor(accesses, permission).AllowsRoute(route, currentGroups())
}

func userCanOnRoute(ctx context.Context, db *sql.DB, userID, permission string, route *router.Route) bool {
	role := UserRole(ctx, db, userID)
	if IsAdminRole(role) {
		return true
	}
	accesses, err := UserAccesses(ctx, db, userID)
	if err != nil {
		return false
	}
	return canOnRoute(role, accesses, permission, route)
}

// CanReadProxy retourne true si l'utilisateur peut voir ce proxy.
func CanReadProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	return userCanOnRoute(ctx, db, userID, "proxies:read", route)
}

// CanReadProxyWithGrants est identique à CanReadProxy mais évite une requête DB quand
// le rôle et les accès sont déjà chargés (utiliser dans les boucles list).
func CanReadProxyWithGrants(role string, grants []Grant, route *router.Route) bool {
	return canOnRoute(role, grants, "proxies:read", route)
}

// CanWriteProxy retourne true si l'utilisateur peut créer/modifier/désactiver ce proxy.
func CanWriteProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	return userCanOnRoute(ctx, db, userID, "proxies:operate", route)
}

// CanWriteProxyWithGrants est identique à CanWriteProxy sans requête DB supplémentaire.
func CanWriteProxyWithGrants(role string, grants []Grant, route *router.Route) bool {
	return canOnRoute(role, grants, "proxies:operate", route)
}

// routeIsL4 detects TCP/UDP streams (host is a free label, not a DNS domain).
func routeIsL4(route *router.Route) bool {
	if route == nil {
		return false
	}
	switch strings.ToLower(string(route.Type)) {
	case "tcp", "udp":
		return true
	}
	return route.ListenPort > 0
}

// CanDeleteProxy retourne true si l'utilisateur peut supprimer ce proxy : le niveau « Gestion » des proxys.
func CanDeleteProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	return userCanOnRoute(ctx, db, userID, "proxies:manage", route)
}

// CanDeleteProxyWithGrants est identique à CanDeleteProxy sans requête DB supplémentaire.
func CanDeleteProxyWithGrants(role string, grants []Grant, route *router.Route) bool {
	return canOnRoute(role, grants, "proxies:manage", route)
}

// CanReadDomainWithGrants retourne true si l'utilisateur peut voir ce domaine.
func CanReadDomainWithGrants(role string, grants []Grant, domain string) bool {
	if IsAdminRole(role) {
		return true
	}
	return FilterFor(grants, "domains:read").Allows(Resource{Hosts: []string{domain}})
}

// --- Droits token (Passerelle/Agent) ---

// TokenScopes retourne les scopes associés à un token (par ID de token).
func TokenScopes(ctx context.Context, db *sql.DB, tokenID string) ([]Scope, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT scope_type, scope_value FROM token_scopes WHERE token_id=?`, tokenID)
	if err != nil {
		return nil, err
	}
	return scanScopes(rows)
}

// TokenRBACRole retourne le rbac_role d'un token (valeur brute du token Bearer).
func TokenRBACRole(ctx context.Context, db *sql.DB, bearerToken string) (tokenID, rbacRole string) {
	db.QueryRowContext(ctx,
		`SELECT id, rbac_role FROM tokens WHERE token=? AND revoked=0
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
		bearerToken,
	).Scan(&tokenID, &rbacRole) //nolint:errcheck
	return
}

// --- Middlewares ---

// RequireAdmin autorise uniquement superadmin et admin (global ou scopé).
func RequireAdmin(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if !IsAdmin(r.Context(), db, userID) {
				http.Error(w, "accès réservé aux administrateurs", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSuperAdmin autorise uniquement le superadmin.
func RequireSuperAdmin(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if !IsSuperAdmin(r.Context(), db, userID) {
				http.Error(w, "accès réservé au super administrateur", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOperator autorise admin/superadmin, ou tout user disposant d'au moins un grant write.
func RequireOperator(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if IsAdmin(r.Context(), db, userID) || UserHasWriteGrant(r.Context(), db, userID) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "accès insuffisant", http.StatusForbidden)
		})
	}
}

// RequireAdminForWrites laisse passer les GET et applique RequireAdmin aux autres méthodes.
// EnforcePATScope ne couvre que les PAT : sans ce garde, une session UI (JWT) d'un user
// pourrait muter certificats, domaines, alertes ou profils IP.
func RequireAdminForWrites(db *sql.DB) func(http.Handler) http.Handler {
	return writesOnly(RequireAdmin(db))
}

// RequireOperatorForWrites laisse passer les GET et applique RequireOperator aux autres méthodes.
func RequireOperatorForWrites(db *sql.DB) func(http.Handler) http.Handler {
	return writesOnly(RequireOperator(db))
}

func writesOnly(guard func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		guarded := guard(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
	}
}

func scanScopes(rows *sql.Rows) ([]Scope, error) {
	defer rows.Close()
	var scopes []Scope
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Type, &s.Value); err == nil {
			scopes = append(scopes, s)
		}
	}
	return scopes, rows.Err()
}

// UserHasWriteGrant indique si une équipe du compte lui donne l'exploitation des proxys : c'est ce qui fait d'un
// utilisateur un « opérateur » (snippets, détecteurs).
func UserHasWriteGrant(ctx context.Context, db *sql.DB, userID string) bool {
	accesses, err := UserAccesses(ctx, db, userID)
	return err == nil && slices.ContainsFunc(accesses, func(a TeamAccess) bool { return a.Grants("proxies:operate") })
}
