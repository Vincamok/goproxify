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

	"github.com/vincamok/goproxify/internal/agent/hostaddr"
)

// ArcaneConfig est la configuration de la source Arcane.
type ArcaneConfig struct {
	URL              string
	APIKey           string
	CACert           string
	Prefix           string
	SkipEnvironments []string
	// EnvironmentHosts : adresse joignable de la passerelle pour un environnement (clé : nom ou identifiant), quand
	// l'adresse d'API qu'Arcane en donne n'est pas résoluble depuis la passerelle (nom de machine interne à Arcane).
	EnvironmentHosts map[string]string
	// RoutableNetworks : sous-réseaux (CIDR) dont les adresses de conteneur sont uniques et joignables depuis la
	// passerelle (macvlan, overlay, VPN). Le conteneur y propose son IP et son port applicatif, avant son port publié.
	RoutableNetworks []string
	// Join dit si le conteneur est sur le Docker de l'Agent et, si oui, connecte la passerelle de cet hôte à ses réseaux :
	// son IP interne est alors joignable. Nil : aucun conteneur n'est considéré local.
	Join func(ctx context.Context, containerID string, networks []string) bool
	// HostAddress rend l'adresse de la machine de l'Agent : un conteneur local qui publie un port y est joint par ce port,
	// que toutes les passerelles d'un groupe HA atteignent. Nil ou vide : l'IP interne.
	HostAddress func(ctx context.Context) string
	Log         *slog.Logger
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
	hosts  map[string]string
	nets   []*net.IPNet

	mu   sync.Mutex
	last map[string][]Instance // identifiant d'environnement → instances du dernier listage réussi
	base string                // collection de l'API : « agents » (Arcane 3) ou « environments » (Arcane 2), apprise au premier listage
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
	hosts := make(map[string]string, len(cfg.EnvironmentHosts))
	for k, v := range cfg.EnvironmentHosts {
		if k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v); k != "" && v != "" {
			hosts[k] = v
		}
	}
	var nets []*net.IPNet
	for _, cidr := range cfg.RoutableNetworks {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("arcane : sous-réseau routable invalide %q", cidr)
		}
		nets = append(nets, n)
	}
	return &Arcane{cfg: cfg, client: c, skip: skip, hosts: hosts, nets: nets, last: map[string][]Instance{}}, nil
}

type arcaneEnvironment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	APIURL  string `json:"apiUrl"`
	Enabled bool   `json:"enabled"`
	// AgentHost : ce que l'agent Arcane de l'hôte déclare de lui-même. PublicIP y porte l'adresse de l'hôte (celle du LAN
	// pour un hôte du réseau local), seule à être sûrement joignable quand l'adresse d'API est un nom que seul Arcane résout.
	AgentHost struct {
		PublicIP string `json:"publicIp"`
	} `json:"agentHost"`
}

type arcanePort struct {
	IP          string `json:"ip"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort"`
	Type        string `json:"type"`
}

type arcaneContainer struct {
	ID              string            `json:"id"`
	Names           []string          `json:"names"`
	Image           string            `json:"image"`
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

// arcaneList lit toutes les pages d'une liste paginée (start/limit). Rend aussi le statut HTTP de l'échec, 0 hors HTTP.
func arcaneList[T any](ctx context.Context, a *Arcane, path string) ([]T, int, error) {
	hdr := map[string]string{"X-API-Key": a.cfg.APIKey}
	var all []T
	for start := 0; ; start += arcanePageSize {
		var page arcanePage[T]
		u := fmt.Sprintf("%s/api%s?start=%d&limit=%d", a.cfg.URL, path, start, arcanePageSize)
		if status, err := doJSON(ctx, a.client, http.MethodGet, u, hdr, nil, &page); err != nil {
			return nil, status, err
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || len(all) >= page.Pagination.TotalItems {
			return all, 0, nil
		}
	}
}

// environments liste les environnements du gestionnaire. Arcane 3 les expose sous /agents, Arcane 2 sous
// /environments : la collection qui répond est retenue, l'autre n'est essayée que si la première est introuvable (404).
func (a *Arcane) environments(ctx context.Context) ([]arcaneEnvironment, error) {
	a.mu.Lock()
	known := a.base
	a.mu.Unlock()
	order := []string{"agents", "environments"}
	if known != "" {
		order = []string{known}
	}
	var lastErr error
	for _, base := range order {
		envs, status, err := arcaneList[arcaneEnvironment](ctx, a, "/"+base)
		if err == nil {
			a.mu.Lock()
			a.base = base
			a.mu.Unlock()
			return envs, nil
		}
		lastErr = err
		if status != http.StatusNotFound {
			break
		}
	}
	return nil, lastErr
}

func (a *Arcane) List(ctx context.Context) ([]Instance, error) {
	envs, err := a.environments(ctx)
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
	a.mu.Lock()
	base := a.base
	a.mu.Unlock()
	conts, _, err := arcaneList[arcaneContainer](ctx, a, "/"+base+"/"+url.PathEscape(env.ID)+"/containers")
	if err != nil {
		return nil, err
	}
	host, forced := arcaneEnvHost(env.APIURL), false
	for _, k := range []string{env.ID, env.Name} {
		if h := a.hosts[strings.ToLower(k)]; h != "" {
			host, forced = h, true
			break
		}
	}
	// Le backend porte une adresse IP : la passerelle ne résout pas toujours le nom d'un hôte interne à Arcane. Un nom
	// que l'Agent ne résout pas cède la place à l'adresse que l'agent Arcane de l'hôte déclare ; un environnement sans
	// adresse d'API exploitable (agent en connexion sortante) prend directement cette adresse.
	declared := ""
	if ip := net.ParseIP(strings.TrimSpace(env.AgentHost.PublicIP)); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		declared = ip.String()
	}
	if name := host; name != "" {
		var ok bool
		switch host, ok = hostaddr.Resolve(name); {
		case ok:
		case declared != "":
			host = declared
		case a.cfg.Log != nil && hostaddr.FirstFailure(name):
			a.cfg.Log.Warn("découverte : nom d'hôte Arcane non résolu depuis l'Agent et sans adresse déclarée par l'agent Arcane, gardé tel quel (renseigner « Adresses des environnements » si la passerelle ne le résout pas non plus)", "environment", env.Name, "host", name)
		}
	} else if declared != "" {
		host = declared
	}
	var out []Instance
	for _, c := range conts {
		if inst, ok := a.instance(ctx, env, host, forced, c); ok {
			out = append(out, inst)
		}
	}
	return out, nil
}

// instance construit l'instance d'un conteneur. Résolution du backend, comme pour Portainer :
//   - étiquette backend : l'URL complète du conteneur ;
//   - environnement distant : le port publié, sur l'adresse précise à laquelle Docker l'a lié, sinon sur l'hôte de l'API de
//     l'environnement (l'IP interne du conteneur n'est pas routable depuis la passerelle) ; `environment_hosts` impose
//     l'adresse d'un environnement, avant tout le reste sauf les étiquettes ;
//   - environnement local : l'IP du conteneur, à défaut son nom (DNS Docker), avec son port applicatif.
//
// L'étiquette « ip » remplace l'adresse dans tous les cas.
func (a *Arcane) instance(ctx context.Context, env arcaneEnvironment, envHost string, forced bool, c arcaneContainer) (Instance, bool) {
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
	bindIP := ""
	labelPort := 0
	if lp, err := strconv.Atoi(labels[p+"port"]); err == nil && lp > 0 {
		labelPort = lp
		port = lp
		if remote {
			if pub, ip := arcanePublishedFor(c.Ports, lp); pub > 0 {
				port, bindIP = pub, ip
			}
		}
	} else if remote {
		port, bindIP = arcaneFirstPort(c.Ports, true)
	} else {
		port, _ = arcaneFirstPort(c.Ports, false)
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
			if !forced && bindIP != "" {
				addr = bindIP
			}
		default:
			addr = arcaneContainerIP(c)
			if addr == "" {
				addr = name
			}
		}
		backend = backendURL(labels, p, addr, port)
	}
	var candidates []string
	if strings.TrimSpace(labels[p+"backend"]) == "" && strings.TrimSpace(labels[p+"ip"]) == "" {
		backend, candidates = a.internalAddress(ctx, c, labels, labelPort, remote, backend)
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
		Key:        env.ID + "/" + c.ID,
		Name:       name + " (" + env.Name + ")",
		Backend:    backend,
		Candidates: candidates,
		Labels:     labels,
		Inactive:   inactive,
		Image:      strings.TrimSpace(c.Image),
	}, true
}

// internalAddress ajoute l'adresse interne du conteneur (IP et port applicatif), quand elle est sûrement joignable :
//   - conteneur sur le Docker de l'Agent : la passerelle de l'hôte rejoint son réseau, l'IP interne est servie, sans port
//     publié à suivre ;
//   - réseau déclaré routable (RoutableNetworks) : l'IP est proposée avant le port publié, que la passerelle sonde (ADR 0026).
//
// Toute autre adresse interne est écartée : un réseau bridge d'un autre hôte n'est pas joignable, et une IP « 172.x »
// sondée depuis la passerelle pourrait tomber sur un autre conteneur de ses propres réseaux.
func (a *Arcane) internalAddress(ctx context.Context, c arcaneContainer, labels map[string]string, labelPort int, remote bool, backend string) (string, []string) {
	p := a.cfg.Prefix
	priv := labelPort
	if priv <= 0 {
		priv, _ = arcaneFirstPort(c.Ports, false)
	}
	ips := arcaneNetworkIPs(c)
	if priv <= 0 || len(ips) == 0 {
		return backend, nil
	}
	at := func(ip string) string {
		l := make(map[string]string, len(labels))
		for k, v := range labels {
			l[k] = v
		}
		l[p+"port"] = strconv.Itoa(priv)
		return backendURL(l, p, ip, priv)
	}

	if a.cfg.Join != nil {
		names := make([]string, 0, len(ips))
		for _, n := range ips {
			names = append(names, n.network)
		}
		if a.cfg.Join(ctx, c.ID, names) {
			if u := a.hostPublished(ctx, c, labels, priv); u != "" {
				return u, nil
			}
			return at(ips[0].ip), nil
		}
	}
	var internal []string
	for _, n := range ips {
		if a.routable(n.ip) {
			if u := at(n.ip); u != "" {
				internal = append(internal, u)
			}
		}
	}
	switch {
	case len(internal) == 0:
		return backend, nil
	case !remote || backend == "":
		return internal[0], nil
	}
	return backend, append(internal, backend)
}

func (a *Arcane) routable(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

type arcaneNetIP struct{ network, ip string }

// arcaneNetworkIPs : les IP du conteneur, par réseau, dans l'ordre alphabétique des réseaux (résultat stable).
func arcaneNetworkIPs(c arcaneContainer) []arcaneNetIP {
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for n := range c.NetworkSettings.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []arcaneNetIP
	for _, n := range names {
		if ip := c.NetworkSettings.Networks[n].IPAddress; ip != "" {
			out = append(out, arcaneNetIP{n, ip})
		}
	}
	return out
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

// arcaneFirstPort rend le premier port TCP du conteneur (publié ou applicatif) et, pour un port publié lié à une
// adresse précise, cette adresse.
func arcaneFirstPort(ports []arcanePort, published bool) (int, string) {
	for _, p := range ports {
		if !strings.EqualFold(p.Type, "tcp") {
			continue
		}
		if published && p.PublicPort > 0 {
			return p.PublicPort, arcaneBindIP(p.IP)
		}
		if !published && p.PrivatePort > 0 {
			return p.PrivatePort, ""
		}
	}
	return 0, ""
}

// arcanePublishedFor rend le port publié pour le port applicatif demandé et l'adresse précise à laquelle il est lié.
func arcanePublishedFor(ports []arcanePort, private int) (int, string) {
	for _, p := range ports {
		if strings.EqualFold(p.Type, "tcp") && p.PrivatePort == private && p.PublicPort > 0 {
			return p.PublicPort, arcaneBindIP(p.IP)
		}
	}
	return 0, ""
}

// arcaneBindIP : l'adresse de liaison d'un port publié, vide quand il écoute partout (0.0.0.0, ::) ou sur la boucle
// locale, qui ne désignent pas l'hôte vu de la passerelle.
func arcaneBindIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if a := net.ParseIP(ip); a == nil || a.IsUnspecified() || a.IsLoopback() {
		return ""
	}
	return ip
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

// hostPublished : l'adresse de la machine de l'Agent et le port que le conteneur y publie pour son port applicatif priv,
// ou vide. Le conteneur est local ; ce chemin est joignable par toutes les passerelles, l'IP interne par celle de l'hôte seule.
func (a *Arcane) hostPublished(ctx context.Context, c arcaneContainer, labels map[string]string, priv int) string {
	if a.cfg.HostAddress == nil {
		return ""
	}
	host := a.cfg.HostAddress(ctx)
	pub, bindIP := arcanePublishedFor(c.Ports, priv)
	if host == "" || pub <= 0 {
		return ""
	}
	if bindIP != "" {
		host = bindIP
	}
	p := a.cfg.Prefix
	l := make(map[string]string, len(labels))
	for k, v := range labels {
		l[k] = v
	}
	l[p+"port"] = strconv.Itoa(pub)
	return backendURL(l, p, host, pub)
}
