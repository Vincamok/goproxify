// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

// SetRoutableNetworks déclare les sous-réseaux (CIDR) de conteneurs dont les adresses sont uniques et joignables depuis la
// passerelle : un conteneur d'un endpoint distant y propose son IP et son port applicatif avant son port publié (ADR 0026).
func (d *Discovery) SetRoutableNetworks(cidrs []string) error {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("portainer : sous-réseau routable invalide %q", cidr)
		}
		nets = append(nets, n)
	}
	d.nets = nets
	return nil
}

// addCandidates ajoute à la route d'un conteneur d'endpoint distant l'adresse interne que la passerelle peut joindre : l'IP
// du conteneur dans un réseau routable déclaré, avec son port applicatif. Rien pour un endpoint local (la passerelle rejoint
// déjà le réseau et l'IP interne est servie), pour une étiquette `backend` ou `ip` (une seule adresse désignée), ni pour un
// conteneur à plusieurs routes. Une IP hors des réseaux déclarés n'est jamais proposée : un bridge d'un autre hôte n'est pas
// joignable, et sondée elle pourrait tomber sur un autre conteneur des réseaux de la passerelle.
func (d *Discovery) addCandidates(c Container, specs []*docker.ProxySpec, isLocal bool) {
	if isLocal || len(d.nets) == 0 || len(specs) != 1 {
		return
	}
	spec := specs[0]
	if spec.BackendURL == "" || c.Labels[docker.LabelBackendURL] != "" || c.Labels[docker.LabelIP] != "" {
		return
	}
	priv, _ := strconv.Atoi(c.Labels[docker.LabelPort])
	if priv <= 0 {
		priv = firstPrivateTCPPort(c.Ports)
	}
	if priv <= 0 {
		return
	}
	scheme := "http"
	if u, err := url.Parse(spec.BackendURL); err == nil && u.Scheme != "" {
		scheme = u.Scheme
	}
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	var cands []string
	for _, name := range names {
		ip := net.ParseIP(c.NetworkSettings.Networks[name].IPAddress)
		if ip == nil || !d.routable(ip) {
			continue
		}
		cands = append(cands, scheme+"://"+net.JoinHostPort(ip.String(), strconv.Itoa(priv)))
	}
	if len(cands) > 0 {
		spec.Candidates = append(cands, spec.BackendURL)
	}
}

func (d *Discovery) routable(ip net.IP) bool {
	for _, n := range d.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SetHostAddress donne l'adresse de la machine de l'Agent : un conteneur d'un endpoint local qui y publie un port est joint
// par elle et ce port, que toutes les passerelles d'un groupe HA atteignent.
func (d *Discovery) SetHostAddress(fn func(context.Context) string) { d.hostAddr = fn }

func (d *Discovery) preferHost(ctx context.Context, c Container, specs []*docker.ProxySpec) {
	if d.hostAddr == nil {
		return
	}
	ports := make([]docker.PortBinding, 0, len(c.Ports))
	for _, p := range c.Ports {
		ports = append(ports, docker.PortBinding{PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type, IP: p.IP})
	}
	docker.PreferHostAddress(specs, c.Labels, ports, d.hostAddr(ctx))
}
