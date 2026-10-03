// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// View est une entrée dédiée du portail (ex. /prestataire, /interne) : même passerelle,
// même annuaire et mêmes destinations, mais apparence, authentification et périmètre propres.
type View struct {
	Slug           string   `json:"slug,omitempty"` // segment d'URL (/prestataire) ; vide si la vue est portée par son hôte
	Host           string   `json:"host,omitempty"` // hôte dédié (optionnel) : portail-presta.example.fr
	Name           string   `json:"name,omitempty"` // libellé d'administration
	Title          string   `json:"title,omitempty"`
	Tagline        string   `json:"tagline,omitempty"`
	Theme          string   `json:"theme,omitempty"`            // vide = thème du portail
	AuthProviderID string   `json:"auth_provider_id,omitempty"` // vide = fournisseur du portail
	AllowedTags    []string `json:"allowed_tags,omitempty"`     // groupes autorisés à se connecter ; vide = tous
	TargetTags     []string `json:"target_tags,omitempty"`      // seules les destinations portant un de ces tags sont visibles ; vide = toutes
	Require2FA     *bool    `json:"require_2fa,omitempty"`      // nil = réglage du portail
}

// ResolvedView est une vue avec ses valeurs héritées du portail.
type ResolvedView struct {
	Key            string // identifiant stable : slug, sinon "@hôte", sinon "" (vue par défaut)
	Slug           string
	Host           string
	Name           string
	Title          string
	Tagline        string
	Theme          string
	AuthProviderID string
	AllowedTags    []string
	TargetTags     []string
	Require2FA     bool
	Default        bool
}

const (
	DefaultViewTitle   = "Accès sécurisé à votre infrastructure"
	DefaultViewTagline = "Sessions SSH et shell à jeton UUID — VM, bare-metal et conteneurs Docker."
)

var viewSlugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// reservedSlugs ne peuvent pas servir d'URL de vue (collision avec l'API ou le portail).
var reservedSlugs = map[string]bool{"api": true, "assets": true, "static": true, "favicon.ico": true}

// NormalizeView nettoie une vue (slug/hôte en minuscules, thème valide, tags sans doublon).
func NormalizeView(v View) View {
	v.Slug = strings.Trim(strings.ToLower(strings.TrimSpace(v.Slug)), "/")
	v.Host = strings.ToLower(strings.TrimSpace(v.Host))
	v.Name = strings.TrimSpace(v.Name)
	v.Title = strings.TrimSpace(v.Title)
	v.Tagline = strings.TrimSpace(v.Tagline)
	v.AuthProviderID = strings.TrimSpace(v.AuthProviderID)
	if strings.TrimSpace(v.Theme) != "" {
		v.Theme = NormalizeTheme(v.Theme)
	} else {
		v.Theme = ""
	}
	v.AllowedTags = cleanTags(v.AllowedTags)
	v.TargetTags = cleanTags(v.TargetTags)
	return v
}

func cleanTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	return out
}

// ValidateViews vérifie la liste des vues : identifiants uniques, slug valide, au moins un slug ou un hôte.
func ValidateViews(views []View) error {
	seen := map[string]bool{}
	for i, v := range views {
		v = NormalizeView(v)
		if v.Slug == "" && v.Host == "" {
			return fmt.Errorf("vue %d : renseignez une URL (slug) ou un hôte", i+1)
		}
		if v.Slug != "" {
			if !viewSlugRe.MatchString(v.Slug) || reservedSlugs[v.Slug] {
				return fmt.Errorf("vue %d : URL %q invalide (lettres minuscules, chiffres et tirets)", i+1, v.Slug)
			}
		}
		if v.Host != "" && (strings.ContainsAny(v.Host, "/ :") || !strings.Contains(v.Host, ".")) {
			return fmt.Errorf("vue %d : hôte %q invalide", i+1, v.Host)
		}
		key := v.Host + "|" + v.Slug
		if seen[key] {
			return fmt.Errorf("vue %d : combinaison hôte/URL déjà utilisée", i+1)
		}
		seen[key] = true
	}
	return nil
}

func viewKey(v View) string {
	if v.Slug != "" {
		return v.Slug
	}
	if v.Host != "" {
		return "@" + v.Host
	}
	return ""
}

func (c *Config) resolved(v View) ResolvedView {
	r := ResolvedView{
		Key: viewKey(v), Slug: v.Slug, Host: v.Host, Name: v.Name,
		Title: v.Title, Tagline: v.Tagline, Theme: NormalizeTheme(c.Theme),
		AuthProviderID: c.AuthProviderID, AllowedTags: v.AllowedTags, TargetTags: v.TargetTags,
		Require2FA: c.Require2FA,
	}
	if v.Theme != "" {
		r.Theme = v.Theme
	}
	if v.AuthProviderID != "" {
		r.AuthProviderID = v.AuthProviderID
	}
	if v.Require2FA != nil {
		r.Require2FA = *v.Require2FA
	}
	if r.Title == "" {
		r.Title = DefaultViewTitle
	}
	if r.Tagline == "" {
		r.Tagline = DefaultViewTagline
	}
	return r
}

// DefaultView est le portail lui-même (racine de l'hôte public).
func (c *Config) DefaultView() ResolvedView {
	r := c.resolved(View{})
	r.Default = true
	return r
}

// ResolveView détermine la vue pour un hôte et un segment d'URL (sans "/").
// Ordre : hôte+slug, slug seul, hôte dédié sans slug, puis le portail par défaut.
func (c *Config) ResolveView(host, slug string) ResolvedView {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	slug = strings.ToLower(strings.Trim(slug, "/"))
	if slug != "" {
		for _, v := range c.Views {
			if v.Slug == slug && v.Host != "" && v.Host == host {
				return c.resolved(v)
			}
		}
		for _, v := range c.Views {
			if v.Slug == slug && v.Host == "" {
				return c.resolved(v)
			}
		}
	}
	if host != "" {
		for _, v := range c.Views {
			if v.Slug == "" && v.Host == host {
				return c.resolved(v)
			}
		}
	}
	return c.DefaultView()
}

// ViewHosts liste les hôtes dédiés des vues (sans doublon, hors hôte public).
func (c *Config) ViewHosts() []string {
	seen := map[string]bool{strings.ToLower(strings.TrimSpace(c.PublicHost)): true}
	var out []string
	for _, v := range c.Views {
		if v.Host != "" && !seen[v.Host] {
			seen[v.Host] = true
			out = append(out, v.Host)
		}
	}
	return out
}

// AllowsUser indique si un utilisateur (par ses tags) peut se connecter à la vue.
func (r ResolvedView) AllowsUser(userTags []string) bool {
	if len(r.AllowedTags) == 0 {
		return true
	}
	return tagsIntersect(userTags, r.AllowedTags)
}

// AllowsTarget indique si une destination (par ses tags) est visible dans la vue.
func (r ResolvedView) AllowsTarget(targetTags []string) bool {
	if len(r.TargetTags) == 0 {
		return true
	}
	return tagsIntersect(targetTags, r.TargetTags)
}

func tagsIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(y)) {
				return true
			}
		}
	}
	return false
}

// Path est l'URL publique de la vue.
func (r ResolvedView) Path() string {
	if r.Slug == "" {
		return "/"
	}
	return "/" + r.Slug
}

// viewFor résout la vue d'une requête API : hôte de la requête + segment d'URL envoyé par la page
// (en-tête X-Portal-View, ou ?view= pour les redirections navigateur).
func (h *HTTPServer) viewFor(r *http.Request) ResolvedView {
	if h.cfg == nil {
		return (&Config{}).DefaultView()
	}
	slug := r.Header.Get("X-Portal-View")
	if slug == "" {
		slug = r.URL.Query().Get("view")
	}
	return h.cfg.ResolveView(r.Host, slug)
}

func oidcStartPath(v ResolvedView) string {
	if v.Slug == "" {
		return "/api/oidc/start"
	}
	return "/api/oidc/start?view=" + url.QueryEscape(v.Slug)
}

// oidcViewSlug lit la vue mémorisée dans le cookie d'état OIDC. La valeur n'est pas encore
// authentifiée : la signature est vérifiée ensuite avec le secret du fournisseur de cette vue,
// donc une valeur altérée est rejetée.
func (h *HTTPServer) oidcViewSlug(cookie string) string {
	raw, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil || len(raw) <= 32 {
		return ""
	}
	var st map[string]string
	if json.Unmarshal(raw[32:], &st) != nil {
		return ""
	}
	return st["view"]
}

// pageHTML rend la page du portail pour une vue (thème, titre et sous-titre injectés côté serveur).
func pageHTML(v ResolvedView) string {
	meta, _ := json.Marshal(map[string]string{"slug": v.Slug, "key": v.Key})
	out := strings.NewReplacer(
		"__PORTAL_THEME__", v.Theme,
		"__PORTAL_VIEW__", string(meta),
		"__PORTAL_TITLE__", htmlEscape(v.Title),
		"__PORTAL_TAGLINE__", htmlEscape(v.Tagline),
	).Replace(portalIndexHTML)
	return out
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;").Replace(s)
}
