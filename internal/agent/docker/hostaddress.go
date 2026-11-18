// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/agent/hostaddr"
)

// HostAddress donne l'adresse de la machine qui porte le Docker de l'Agent, celle que les passerelles joignent pour un
// port publié. L'Agent, dans son conteneur, ne voit que son adresse sur le réseau Docker : l'adresse de l'hôte vient de
// `host_address` (IP ou nom) quand elle est configurée, sinon du nom de la machine que Docker rapporte, résolu par le DNS.
type HostAddress struct {
	client     *Client
	configured string
	log        *slog.Logger

	mu     sync.Mutex
	addr   string
	at     time.Time
	logged bool
}

const hostAddressTTL = 5 * time.Minute

// NewHostAddress crée le résolveur. configured : `host_address`, vide pour la déduire. log peut être nil.
func NewHostAddress(client *Client, configured string, log *slog.Logger) *HostAddress {
	return &HostAddress{client: client, configured: strings.TrimSpace(configured), log: log}
}

// Get rend l'adresse de l'hôte, ou vide quand elle est inconnue (nom de machine non résolu, aucune configuration).
func (h *HostAddress) Get(ctx context.Context) string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	if !h.at.IsZero() && time.Since(h.at) < hostAddressTTL {
		addr := h.addr
		h.mu.Unlock()
		return addr
	}
	h.mu.Unlock()

	addr := h.lookup(ctx)

	h.mu.Lock()
	changed := !h.logged || addr != h.addr
	h.addr, h.at, h.logged = addr, time.Now(), true
	h.mu.Unlock()
	if changed && h.log != nil {
		if addr != "" {
			h.log.Info("docker: adresse de l'hôte", "adresse", addr, "configurée", h.configured != "")
		} else {
			h.log.Warn("docker: adresse de l'hôte inconnue, l'IP interne des conteneurs locaux est gardée (renseigner « Adresse de l'hôte » ou GPX_HOST_ADDRESS pour joindre leur port publié)")
		}
	}
	return addr
}

func (h *HostAddress) lookup(ctx context.Context) string {
	if h.configured != "" {
		addr, _ := hostaddr.Resolve(h.configured)
		return addr
	}
	if h.client == nil {
		return ""
	}
	var info struct {
		Name string `json:"Name"`
	}
	if h.client.Get(ctx, "/info", &info) != nil || strings.TrimSpace(info.Name) == "" {
		return ""
	}
	addr, ok := hostaddr.Resolve(strings.TrimSpace(info.Name))
	if !ok || !usableHostIP(addr) {
		return ""
	}
	return addr
}

// usableHostIP écarte ce qui ne désigne pas la machine pour les autres : boucle locale, adresse non spécifiée, lien local.
func usableHostIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

// PreferHostAddress remplace l'adresse interne d'une route par l'adresse de l'hôte et le port publié du conteneur, quand le
// conteneur en publie un : ce chemin est joignable par toutes les passerelles d'un groupe HA, sans étiquette `backend`, alors
// que l'IP interne n'est joignable que depuis l'hôte du conteneur. Sans port publié, l'adresse interne reste.
//
// Seules les routes HTTP d'un conteneur à route unique sans étiquette `backend` ni `ip` sont concernées. Un port publié sur
// la boucle locale seule n'est joignable que depuis l'hôte : il est ignoré ; lié à une adresse précise, c'est cette adresse.
func PreferHostAddress(specs []*ProxySpec, labels map[string]string, ports []PortBinding, host string) {
	if host == "" || len(specs) != 1 {
		return
	}
	spec := specs[0]
	if (spec.Type != "" && spec.Type != "http") || spec.Port <= 0 {
		return
	}
	if labels[LabelBackendURL] != "" || labels[LabelIP] != "" {
		return
	}
	for _, p := range ports {
		if !strings.EqualFold(p.Type, "tcp") || p.PrivatePort != spec.Port || p.PublicPort <= 0 {
			continue
		}
		addr := host
		if ip := net.ParseIP(strings.TrimSpace(p.IP)); ip != nil && !ip.IsUnspecified() {
			if ip.IsLoopback() {
				continue
			}
			addr = ip.String()
		}
		scheme := "http"
		if u, err := url.Parse(spec.BackendURL); err == nil && u.Scheme != "" {
			scheme = u.Scheme
		}
		spec.BackendURL = scheme + "://" + net.JoinHostPort(addr, strconv.Itoa(p.PublicPort))
		return
	}
}
