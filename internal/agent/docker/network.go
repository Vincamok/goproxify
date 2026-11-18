// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/agent/hostaddr"
)

// NetworkManager connecte le conteneur passerelle aux réseaux Docker des apps découvertes.
//
// Le conteneur passerelle est retrouvé seul : c'est celui qui porte l'adresse de la passerelle de l'Agent (son nom, ou l'IP
// qu'un nom ou un alias Docker désigne). Un nom configuré (`network_management.edge_container_name`) reste prioritaire.
type NetworkManager struct {
	client     *Client
	configured string
	log        *slog.Logger

	mu        sync.Mutex
	hostsFn   func() []string
	connected map[string]bool // réseau@conteneur passerelle → déjà connecté
	edgeName  string
	edgeID    string
	edgeAt    time.Time
}

const (
	edgeFoundTTL    = time.Minute
	edgeNotFoundTTL = 15 * time.Second
)

// NewNetworkManager crée un NetworkManager. configured : nom du conteneur passerelle imposé, vide pour le retrouver seul.
func NewNetworkManager(client *Client, configured string, log *slog.Logger) *NetworkManager {
	return &NetworkManager{client: client, configured: configured, log: log, connected: make(map[string]bool)}
}

// SetEdgeHosts donne les adresses des passerelles de l'Agent (la courante en premier) : le conteneur passerelle de cet
// hôte est celui qui en porte une.
func (m *NetworkManager) SetEdgeHosts(fn func() []string) {
	m.mu.Lock()
	m.hostsFn = fn
	m.mu.Unlock()
}

// edge rend le nom et l'identifiant du conteneur passerelle présent sur ce Docker, vides s'il n'y en a pas. Le résultat est
// gardé une minute (15 s quand rien n'est trouvé) : une passerelle recréée est retrouvée sans redémarrer l'Agent.
func (m *NetworkManager) edge(ctx context.Context) (string, string) {
	if m == nil || m.client == nil {
		return "", ""
	}
	m.mu.Lock()
	ttl := edgeFoundTTL
	if m.edgeID == "" {
		ttl = edgeNotFoundTTL
	}
	if !m.edgeAt.IsZero() && time.Since(m.edgeAt) < ttl {
		name, id := m.edgeName, m.edgeID
		m.mu.Unlock()
		return name, id
	}
	configured, hostsFn := m.configured, m.hostsFn
	m.mu.Unlock()

	name, id := m.findEdge(ctx, configured, hostsFn)

	m.mu.Lock()
	changed := id != m.edgeID
	m.edgeName, m.edgeID, m.edgeAt = name, id, time.Now()
	m.mu.Unlock()
	if changed && id != "" && m.log != nil {
		m.log.Info("docker: conteneur passerelle de cet hôte", "edge", name)
	}
	return name, id
}

func (m *NetworkManager) findEdge(ctx context.Context, configured string, hostsFn func() []string) (string, string) {
	if configured != "" {
		var info struct {
			ID string `json:"Id"`
		}
		if m.client.Get(ctx, "/containers/"+configured+"/json", &info) != nil || info.ID == "" {
			return "", ""
		}
		return configured, info.ID
	}
	if hostsFn == nil {
		return "", ""
	}
	var list []ContainerSummary
	if m.client.Get(ctx, "/containers/json", &list) != nil {
		return "", ""
	}
	return matchEdgeContainer(list, hostsFn(), func(h string) string { ip, _ := hostaddr.Resolve(h); return ip })
}

// matchEdgeContainer cherche, parmi les conteneurs de ce Docker, celui qui porte l'adresse d'une des passerelles : son nom,
// ou l'IP qu'a l'hôte de l'adresse (un nom ou un alias Docker se résout en l'IP du conteneur). resolve rend l'IP d'un nom.
func matchEdgeContainer(list []ContainerSummary, endpoints []string, resolve func(string) string) (string, string) {
	sort.Slice(list, func(i, j int) bool { return firstName(list[i].Names) < firstName(list[j].Names) })
	for _, ep := range endpoints {
		u, err := url.Parse(ep)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		ip := host
		if net.ParseIP(host) == nil {
			ip = resolve(host)
		}
		for _, c := range list {
			name := strings.TrimPrefix(firstName(c.Names), "/")
			if strings.EqualFold(name, host) {
				return name, c.ID
			}
			for _, n := range c.NetworkSettings.Networks {
				if ip != "" && n.IPAddress == ip {
					return name, c.ID
				}
			}
		}
	}
	return "", ""
}

// Joinable dit si la passerelle de cet hôte peut rejoindre le réseau du conteneur d'identifiant containerID : elle tourne sur
// le Docker de l'Agent, et le conteneur aussi. Faux dans tous les autres cas : l'adresse interne du conteneur n'est alors
// pas joignable par la passerelle, et ne doit pas être utilisée.
func (m *NetworkManager) Joinable(ctx context.Context, containerID string) bool {
	if _, id := m.edge(ctx); id == "" || containerID == "" {
		return false
	}
	var target struct {
		ID string `json:"Id"`
	}
	return m.client.Get(ctx, "/containers/"+containerID+"/json", &target) == nil && target.ID != ""
}

// ConnectEdgeToNetwork connecte la passerelle au réseau Docker s'il n'y est pas déjà.
func (m *NetworkManager) ConnectEdgeToNetwork(ctx context.Context, networkID string) error {
	name, id := m.edge(ctx)
	if networkID == "" || id == "" {
		return nil
	}
	key := networkID + "@" + id

	m.mu.Lock()
	if m.connected[key] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	err := m.client.Post(ctx, "/networks/"+networkID+"/connect", NetworkConnectBody{Container: id}, nil)
	if err != nil {
		// 403 / 409 = déjà connecté — pas une vraie erreur
		return nil
	}

	m.mu.Lock()
	m.connected[key] = true
	m.mu.Unlock()

	m.log.Info("docker: Passerelle connectée au réseau", "network", networkID, "edge", name)
	return nil
}

// DisconnectEdgeFromNetwork déconnecte la passerelle d'un réseau Docker.
func (m *NetworkManager) DisconnectEdgeFromNetwork(ctx context.Context, networkID string) error {
	_, id := m.edge(ctx)
	if networkID == "" || id == "" {
		return nil
	}
	err := m.client.Post(ctx, "/networks/"+networkID+"/disconnect", NetworkConnectBody{Container: id}, nil)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.connected, networkID+"@"+id)
	m.mu.Unlock()
	m.log.Info("docker: Passerelle déconnecté du réseau", "network", networkID)
	return nil
}
