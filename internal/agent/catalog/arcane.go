// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ArcaneConfig est la configuration de la source Arcane.
type ArcaneConfig struct {
	URL              string
	APIKey           string
	CACert           string
	Prefix           string
	SkipEnvironments []string
	Log              *slog.Logger
}

// Arcane liste les conteneurs de tous les environnements d'un gestionnaire Arcane (API REST, clé d'API en X-API-Key),
// comme la source Portainer le fait pour ses endpoints : l'Agent ne s'installe pas sur les hôtes distants.
// Les étiquettes de route sont les étiquettes Docker « goproxify.clé=valeur » du conteneur.
//
// Un environnement qui ne répond pas n'a pas perdu ses conteneurs : ses dernières instances connues sont conservées
// pour que ses routes ne soient pas retirées, sans bloquer la mise à jour des autres environnements.
type Arcane struct {
	cfg    ArcaneConfig
	client *http.Client
	skip   map[string]bool

	mu   sync.Mutex
	last map[string][]Instance // identifiant d'environnement → instances du dernier listage réussi
}

func NewArcane(cfg ArcaneConfig) (*Arcane, error) {
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if cfg.URL == "" {
		return nil, fmt.Errorf("arcane : url requise")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("arcane : clé d'API requise")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goproxify."
	}
	c, err := newHTTPClient(cfg.CACert)
	if err != nil {
		return nil, err
	}
	skip := make(map[string]bool, len(cfg.SkipEnvironments))
	for _, s := range cfg.SkipEnvironments {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			skip[s] = true
		}
	}
	return &Arcane{cfg: cfg, client: c, skip: skip, last: map[string][]Instance{}}, nil
}

type arcaneEnvironment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	APIURL  string `json:"apiUrl"`
	Enabled bool   `json:"enabled"`
}

type arcanePort struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort"`
	Type        string `json:"type"`
}

type arcaneContainer struct {
	ID              string            `json:"id"`
	Names           []string          `json:"names"`
	Labels          map[string]string `json:"labels"`
	State           string            `json:"state"`
	Ports           []arcanePort      `json:"ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"ipAddress"`
		} `json:"networks"`
	} `json:"networkSettings"`
}

type arcanePage[T any] struct {
	Data       []T `json:"data"`
	Pagination struct {
		TotalItems int `json:"totalItems"`
	} `json:"pagination"`
}

const arcanePageSize = 100

// arcaneList lit toutes les pages d'une liste paginée (start/limit).
func arcaneList[T any](ctx context.Context, a *Arcane, path string) ([]T, error) {
	hdr := map[string]string{"X-API-Key": a.cfg.APIKey}
	var all []T
	for start := 0; ; start += arcanePageSize {
		var page arcanePage[T]
		u := fmt.Sprintf("%s/api%s?start=%d&limit=%d", a.cfg.URL, path, start, arcanePageSize)
		if _, err := doJSON(ctx, a.client, http.MethodGet, u, hdr, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || len(all) >= page.Pagination.TotalItems {
			return all, nil
		}
	}
}

func (a *Arcane) List(ctx context.Context) ([]Instance, error) {
	envs, err := arcaneList[arcaneEnvironment](ctx, a, "/environments")
	if err != nil {
		return nil, err
	}
	sort.Slice(envs, func(i, j int) bool { return envs[i].ID < envs[j].ID })

	seen := make(map[string]bool, len(envs))
	var out []Instance
	for _, env := range envs {
		if !env.Enabled || a.skip[strings.ToLower(env.ID)] || a.skip[strings.ToLower(env.Name)] {
			continue
		}
		seen[env.ID] = true
		insts, err := a.listEnvironment(ctx, env)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			a.mu.Lock()
			insts = a.last[env.ID]
			a.mu.Unlock()
			if a.cfg.Log != nil {
				a.cfg.Log.Warn("découverte : environnement Arcane injoignable, routes conservées", "environment", env.Name, "err", err)
			}
		} else {
			a.mu.Lock()
			a.last[env.ID] = insts
			a.mu.Unlock()
		}
		out = append(out, insts...)
	}
	a.mu.Lock()
	for id := range a.last {
		if !seen[id] {
			delete(a.last, id)
		}
	}
	a.mu.Unlock()
	return out, nil
}

func (a *Arcane) listEnvironment(ctx context.Context, env arcaneEnvironment) ([]Instance, error) {
	conts, err := arcaneList[arcaneContainer](ctx, a, "/environments/"+url.PathEscape(env.ID)+"/containers")
	if err != nil {
		return nil, err
	}
	host := arcaneEnvHost(env.APIURL)
	var out []Instance
	for _, c := range conts {
		if inst, ok := a.instance(env, host, c); ok {
			out = append(out, inst)
		}
	}
	return out, nil
}

// instance construit l'instance d'un conteneur. Résolution du backend, comme pour Portainer :
//   - étiquette backend : l'URL complète du conteneur ;
//   - environnement distant : l'hôte de l'API de l'environnement et le port publié (l'IP interne du conteneur n'est pas
//     routable depuis la passerelle) ;
//   - environnement local : l'IP du conteneur, à défaut son nom (DNS Docker), avec son port applicatif.
//
// L'étiquette « ip » remplace l'adresse dans tous les cas.
func (a *Arcane) instance(env arcaneEnvironment, envHost string, c arcaneContainer) (Instance, bool) {
	p := a.cfg.Prefix
	labels := map[string]string{}
	for k, v := range c.Labels {
		if strings.HasPrefix(k, p) {
			labels[k] = v
		}
	}
	if !strings.EqualFold(labels[p+"enable"], "true") && !strings.EqualFold(labels[p+"enabled"], "true") {
		return Instance{}, false
	}
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	if name == "" {
		name = shortID(c.ID)
	}

	remote := envHost != ""
	port := 0
	if lp, err := strconv.Atoi(labels[p+"port"]); err == nil && lp > 0 {
		port = lp
		if remote {
			if pub := arcanePublishedFor(c.Ports, lp); pub > 0 {
				port = pub
			}
		}
	} else if remote {
		port = arcaneFirstPort(c.Ports, true)
	} else {
		port = arcaneFirstPort(c.Ports, false)
	}
	if port > 0 {
		labels[p+"port"] = strconv.Itoa(port)
	}

	backend := strings.TrimSpace(labels[p+"backend"])
	if backend == "" {
		addr := strings.TrimSpace(labels[p+"ip"])
		switch {
		case addr != "":
		case remote:
			addr = envHost
		default:
			addr = arcaneContainerIP(c)
			if addr == "" {
				addr = name
			}
		}
		backend = backendURL(labels, p, addr, port)
	}
	inactive := ""
	if s := strings.ToLower(strings.TrimSpace(c.State)); s != "" && s != "running" {
		inactive = s
		if backend == "" {
			backend = backendURL(labels, p, name, 80)
		}
	}
	if backend == "" {
		return Instance{}, false
	}
	return Instance{
		Key:      env.ID + "/" + c.ID,
		Name:     name + " (" + env.Name + ")",
		Backend:  backend,
		Labels:   labels,
		Inactive: inactive,
	}, true
}

// arcaneEnvHost extrait l'hôte de l'API d'un environnement. Vide pour un environnement local (localhost, boucle locale,
// socket) ou sans adresse exploitable (agent en connexion sortante).
func arcaneEnvHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "unix" || u.Scheme == "npipe" {
		return ""
	}
	h := u.Hostname()
	if h == "" || strings.EqualFold(h, "localhost") {
		return ""
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return ""
	}
	return h
}

func arcaneFirstPort(ports []arcanePort, published bool) int {
	for _, p := range ports {
		if !strings.EqualFold(p.Type, "tcp") {
			continue
		}
		if published && p.PublicPort > 0 {
			return p.PublicPort
		}
		if !published && p.PrivatePort > 0 {
			return p.PrivatePort
		}
	}
	return 0
}

func arcanePublishedFor(ports []arcanePort, private int) int {
	for _, p := range ports {
		if strings.EqualFold(p.Type, "tcp") && p.PrivatePort == private && p.PublicPort > 0 {
			return p.PublicPort
		}
	}
	return 0
}

// arcaneContainerIP : IP du conteneur dans son premier réseau (par ordre alphabétique, pour un résultat stable).
func arcaneContainerIP(c arcaneContainer) string {
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for n := range c.NetworkSettings.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if ip := c.NetworkSettings.Networks[n].IPAddress; ip != "" {
			return ip
		}
	}
	return ""
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
