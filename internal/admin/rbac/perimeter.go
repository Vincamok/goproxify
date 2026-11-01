// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Périmètre d'un accès d'équipe (ADR 0022, section 2) : un ensemble de critères, tous requis. Un périmètre vide
// couvre tout. Un critère posé sur une dimension que la ressource n'a pas (un proxy sans étiquette face à un critère
// d'étiquette) ne la couvre pas.

// GroupRef décrit un groupe de passerelles tel que le périmètre le juge : son nom et ses attributs. Une passerelle
// isolée est un groupe d'un membre (ADR 0014).
type GroupRef struct {
	Name        string   `json:"name"`
	Environment string   `json:"environment,omitempty"`
	Region      string   `json:"region,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// GroupCriterion désigne des groupes par leur nom (glob) ou leurs attributs ; les champs posés sont tous requis et le
// critère est satisfait quand un seul groupe servant la ressource les réunit.
type GroupCriterion struct {
	Name        string `json:"name,omitempty"`
	Environment string `json:"environment,omitempty"`
	Region      string `json:"region,omitempty"`
	Tag         string `json:"tag,omitempty"`
}

func (c GroupCriterion) empty() bool { return c == GroupCriterion{} }

func (c GroupCriterion) matches(g GroupRef) bool {
	if c.Name != "" && !globMatch(c.Name, g.Name) {
		return false
	}
	if c.Environment != "" && !strings.EqualFold(c.Environment, g.Environment) {
		return false
	}
	if c.Region != "" && !strings.EqualFold(c.Region, g.Region) {
		return false
	}
	if c.Tag != "" && !slices.ContainsFunc(g.Tags, func(t string) bool { return strings.EqualFold(t, c.Tag) }) {
		return false
	}
	return true
}

// Perimeter est l'ensemble des critères d'un accès.
type Perimeter struct {
	// Domain est un glob sur l'hôte ou un alias de la route (le joker DNS « *.corp.io » couvre un seul label).
	Domain string `json:"domain,omitempty"`
	// Proxy désigne un proxy par son identifiant, par un glob sur son nom, ou par une expression régulière RE2
	// préfixée « re: » (non ancrée : écrire ^ et $ pour une correspondance exacte).
	Proxy string `json:"proxy,omitempty"`
	// Backend est un glob sur l'URL d'un backend.
	Backend string `json:"backend,omitempty"`
	// Group désigne les groupes de passerelles qui servent la ressource.
	Group GroupCriterion `json:"group,omitempty"`
	// Labels : chaque paire doit être portée par la ressource.
	Labels map[string]string `json:"labels,omitempty"`
}

// Resource est ce qu'un périmètre sait lire d'un objet : le descripteur de ressource de l'ADR 0022.
type Resource struct {
	Hosts     []string
	ProxyID   string
	ProxyName string
	Backends  []string
	Groups    []GroupRef
	Labels    map[string]string
}

// ProxyName est le nom sous lequel un proxy se désigne dans un périmètre : le nom que l'on lui a donné, à défaut son hôte.
func ProxyName(route *router.Route) string {
	if route.Name != "" {
		return route.Name
	}
	return route.Host
}

// RouteResource décrit un proxy pour un périmètre ; groups sont les groupes de passerelles qui le servent.
func RouteResource(route *router.Route, groups []GroupRef) Resource {
	res := Resource{ProxyID: route.ID, ProxyName: ProxyName(route), Groups: groups, Labels: route.Labels}
	if route.Host != "" {
		res.Hosts = append(res.Hosts, route.Host)
	}
	res.Hosts = append(res.Hosts, route.Aliases...)
	for _, b := range route.Backends {
		res.Backends = append(res.Backends, b.URL)
	}
	return res
}

// IsEmpty dit que le périmètre ne pose aucun critère : il couvre tout.
func (p Perimeter) IsEmpty() bool {
	return p.Domain == "" && p.Proxy == "" && p.Backend == "" && p.Group.empty() && len(p.Labels) == 0
}

// Matches dit si la ressource est dans le périmètre : tous les critères posés doivent la retenir.
func (p Perimeter) Matches(res Resource) bool {
	if p.Domain != "" && !slices.ContainsFunc(res.Hosts, func(h string) bool { return hostMatchesDomainScope(p.Domain, h) }) {
		return false
	}
	if p.Proxy != "" && !proxyMatches(p.Proxy, res) {
		return false
	}
	if p.Backend != "" && !slices.ContainsFunc(res.Backends, func(u string) bool { return globMatch(p.Backend, u) }) {
		return false
	}
	if !p.Group.empty() && !slices.ContainsFunc(res.Groups, p.Group.matches) {
		return false
	}
	for k, v := range p.Labels {
		if got, ok := res.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

const regexPrefix = "re:"

func proxyMatches(criterion string, res Resource) bool {
	if expr, ok := strings.CutPrefix(criterion, regexPrefix); ok {
		re, err := regexp.Compile(expr)
		return err == nil && res.ProxyName != "" && re.MatchString(res.ProxyName)
	}
	if res.ProxyID != "" && criterion == res.ProxyID {
		return true
	}
	return res.ProxyName != "" && globMatch(criterion, res.ProxyName)
}

func globMatch(pattern, value string) bool {
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

// Validate refuse un périmètre dont un critère ne peut pas s'évaluer : glob mal formé, expression régulière qui ne
// compile pas, étiquette invalide. À appeler à l'enregistrement d'un accès.
func (p Perimeter) Validate() error {
	if p.Domain != "" {
		if _, err := path.Match(strings.ToLower(p.Domain), ""); err != nil {
			return fmt.Errorf("domaine %q : %w", p.Domain, err)
		}
	}
	if expr, ok := strings.CutPrefix(p.Proxy, regexPrefix); ok {
		if expr == "" {
			return fmt.Errorf("proxy : expression régulière vide")
		}
		if _, err := regexp.Compile(expr); err != nil {
			return fmt.Errorf("proxy : expression régulière invalide : %w", err)
		}
	} else if p.Proxy != "" {
		if _, err := path.Match(p.Proxy, ""); err != nil {
			return fmt.Errorf("proxy %q : %w", p.Proxy, err)
		}
	}
	if p.Backend != "" {
		if _, err := path.Match(p.Backend, ""); err != nil {
			return fmt.Errorf("backend %q : %w", p.Backend, err)
		}
	}
	if p.Group.Name != "" {
		if _, err := path.Match(p.Group.Name, ""); err != nil {
			return fmt.Errorf("groupe %q : %w", p.Group.Name, err)
		}
	}
	return ValidateLabels(p.Labels)
}

var (
	labelKey   = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?$`)
	labelValue = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,63}$`)
)

const maxLabels = 32

// ValidateLabels vérifie les étiquettes d'un proxy ou d'un critère : clé en minuscules (63 caractères au plus), valeur
// alphanumérique avec « _ », « . » et « - » (63 au plus), 32 étiquettes au plus.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > maxLabels {
		return fmt.Errorf("%d étiquettes : %d au plus", len(labels), maxLabels)
	}
	for k, v := range labels {
		if !labelKey.MatchString(k) {
			return fmt.Errorf("étiquette %q : clé invalide (minuscules, chiffres, « _ », « . », « - », 63 caractères au plus)", k)
		}
		if !labelValue.MatchString(v) {
			return fmt.Errorf("étiquette %s=%q : valeur invalide (lettres, chiffres, « _ », « . », « - », 63 caractères au plus)", k, v)
		}
	}
	return nil
}

// ParseLabelSelector lit « clé=valeur » (l'écriture d'un critère d'étiquette dans l'interface et la CLI).
func ParseLabelSelector(s string) (key, value string, err error) {
	k, v, ok := strings.Cut(strings.TrimSpace(s), "=")
	if !ok {
		return "", "", fmt.Errorf("étiquette %q : attendu clé=valeur", s)
	}
	if err := ValidateLabels(map[string]string{k: v}); err != nil {
		return "", "", err
	}
	return k, v, nil
}

// Preview liste les proxys qu'un périmètre couvre : c'est le « ce périmètre couvre N proxys » de la fenêtre d'un accès.
func (p Perimeter) Preview(routes []router.Route, groups GroupCatalog) []router.Route {
	var out []router.Route
	for i := range routes {
		var gs []GroupRef
		if groups != nil && !p.Group.empty() {
			gs = groups.GroupsServing(&routes[i])
		}
		if p.Matches(RouteResource(&routes[i], gs)) {
			out = append(out, routes[i])
		}
	}
	return out
}

const maxGroupTags = 16

// ValidateGroupAttributes vérifie les attributs d'un groupe de passerelles : environnement et région sont des mots
// comme une valeur d'étiquette ; au plus 16 étiquettes (tags) du même type, sans doublon.
func ValidateGroupAttributes(environment, region string, tags []string) error {
	for name, v := range map[string]string{"environnement": environment, "région": region} {
		if !labelValue.MatchString(v) {
			return fmt.Errorf("%s %q : lettres, chiffres, « _ », « . », « - », 63 caractères au plus", name, v)
		}
	}
	if len(tags) > maxGroupTags {
		return fmt.Errorf("%d tags : %d au plus", len(tags), maxGroupTags)
	}
	seen := map[string]bool{}
	for _, t := range tags {
		if t == "" || !labelValue.MatchString(t) {
			return fmt.Errorf("tag %q : lettres, chiffres, « _ », « . », « - », 63 caractères au plus", t)
		}
		if seen[strings.ToLower(t)] {
			return fmt.Errorf("tag %q en double", t)
		}
		seen[strings.ToLower(t)] = true
	}
	return nil
}
