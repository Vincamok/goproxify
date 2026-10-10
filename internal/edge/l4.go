// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/stream"
)

// Rapprochement des écouteurs TCP/UDP avec la table de routage. Les routes de type tcp et udp portent un
// listen_port : la passerelle y ouvre un écouteur L4 (paquet stream) tant que la route existe, le ferme quand
// elle disparaît et le recrée quand son backend ou ses plugins changent.

// l4State est l'état du rapprochement : signature de chaque écouteur ouvert, compteurs partagés, minuteur de
// regroupement. Il est protégé par son propre verrou ; la table des écouteurs (s.tcpPorts) l'est par s.mu.
type l4State struct {
	mu      sync.Mutex
	timer   *time.Timer
	sigs    map[string]string
	metrics stream.Metrics
	stopped bool
}

// stop empêche tout rapprochement ultérieur (arrêt de la passerelle).
func (l *l4State) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	if l.timer != nil {
		l.timer.Stop()
	}
}

const l4Debounce = 200 * time.Millisecond

// scheduleL4Sync regroupe les modifications rapprochées de la table en un seul rapprochement.
func (s *Server) scheduleL4Sync() {
	s.l4.mu.Lock()
	defer s.l4.mu.Unlock()
	if s.l4.timer != nil {
		s.l4.timer.Stop()
	}
	s.l4.timer = time.AfterFunc(l4Debounce, s.syncL4Listeners)
}

func l4Key(proto string, port int) string { return proto + "/" + strconv.Itoa(port) }

func l4Signature(r *router.Route) string {
	b, _ := json.Marshal(struct {
		ID       string
		Backends []router.Backend
		Plugins  []router.PluginRef
	}{r.ID, r.Backends, r.Plugins})
	return string(b)
}

// syncL4Listeners aligne les écouteurs sur la table : un écouteur par route tcp/udp.
func (s *Server) syncL4Listeners() {
	if s.table == nil {
		return
	}
	desired := map[string]*router.Route{}
	for _, r := range s.table.All() {
		if r.ListenPort <= 0 {
			continue
		}
		switch r.Type {
		case router.RouteTCP:
			desired[l4Key("tcp", r.ListenPort)] = r
		case router.RouteUDP:
			desired[l4Key("udp", r.ListenPort)] = r
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpPorts == nil {
		s.tcpPorts = map[string]interface{ Stop() }{}
	}
	s.l4.mu.Lock()
	if s.l4.stopped {
		s.l4.mu.Unlock()
		return
	}
	if s.l4.sigs == nil {
		s.l4.sigs = map[string]string{}
	}
	sigs, metrics := s.l4.sigs, &s.l4.metrics
	s.l4.mu.Unlock()

	for key, ln := range s.tcpPorts {
		r, want := desired[key]
		if want && sigs[key] == l4Signature(r) {
			continue
		}
		ln.Stop()
		delete(s.tcpPorts, key)
		delete(sigs, key)
		s.log.Info("L4: écouteur fermé", "key", key)
	}
	for key, r := range desired {
		if _, ok := s.tcpPorts[key]; ok {
			continue
		}
		var (
			ln    interface{ Stop() }
			start func() error
		)
		if r.Type == router.RouteTCP {
			l := stream.NewTCPListener(r, s.log.Logger(), metrics)
			l.Gate = s.l4Gate(r.ID, "tcp")
			ln, start = l, l.Start
		} else {
			l := stream.NewUDPListener(r, s.log.Logger(), metrics)
			l.Gate = cachedGate(s.l4Gate(r.ID, "udp"), time.Second)
			ln, start = l, l.Start
		}
		if err := start(); err != nil {
			s.log.Error("L4: ouverture de l'écouteur impossible", "route", r.ID, "key", key, "err", err)
			continue
		}
		s.tcpPorts[key] = ln
		sigs[key] = l4Signature(r)
	}
}

// l4Gate construit le contrôle d'accès d'une route L4 : les plugins qui déclarent le hook connect décident,
// dans l'ordre. Un plugin absent de la passerelle refuse (comme pour une route HTTP) ; un plugin en échec suit
// son on_error. Sans plugin, tout passe.
func (s *Server) l4Gate(routeID, proto string) func(net.Addr) bool {
	return func(client net.Addr) bool {
		route, ok := s.table.ByID(routeID)
		if !ok || len(route.Plugins) == 0 {
			return true
		}
		active, missing, ok := s.resolvePlugins(route)
		if !ok {
			s.log.Error("plugin introuvable, connexion refusée", "route", routeID, "plugin", missing)
			return false
		}
		host, _, err := net.SplitHostPort(client.String())
		if err != nil {
			host = client.String()
		}
		in := plugins.ConnectInput{ClientIP: host, Protocol: proto, ListenPort: route.ListenPort, RouteID: route.ID}
		for _, a := range active {
			if !a.p.Manifest.Has(plugins.HookConnect) {
				continue
			}
			in.Config = a.cfg
			out, err := a.p.Evaluate(context.Background(), plugins.HookConnect, in)
			if err != nil {
				s.log.Warn("plugin en échec", "route", routeID, "plugin", a.p.Manifest.Name, "hook", "connect", "err", err)
			}
			if out.Action == plugins.ActionDeny {
				return false
			}
		}
		return true
	}
}

// cachedGate mémorise la décision par adresse source pendant ttl : en UDP, chaque datagramme passerait sinon par
// un appel de plugin.
func cachedGate(gate func(net.Addr) bool, ttl time.Duration) func(net.Addr) bool {
	type verdict struct {
		allow   bool
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[string]verdict{}
	return func(client net.Addr) bool {
		host, _, err := net.SplitHostPort(client.String())
		if err != nil {
			host = client.String()
		}
		now := time.Now()
		mu.Lock()
		if v, ok := cache[host]; ok && now.Before(v.expires) {
			mu.Unlock()
			return v.allow
		}
		if len(cache) > 4096 {
			for k, v := range cache {
				if !now.Before(v.expires) {
					delete(cache, k)
				}
			}
		}
		mu.Unlock()
		allow := gate(client)
		mu.Lock()
		cache[host] = verdict{allow: allow, expires: now.Add(ttl)}
		mu.Unlock()
		return allow
	}
}
