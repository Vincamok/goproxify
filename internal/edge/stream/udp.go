// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	// DefaultMaxUDPSessions borne les sessions UDP simultanées d'un écouteur (GPX_STREAM_UDP_SESSIONS).
	DefaultMaxUDPSessions = 4096
	// DefaultUDPIdle : une session sans datagramme depuis cette durée est fermée (GPX_STREAM_UDP_IDLE, en secondes).
	DefaultUDPIdle = 60 * time.Second
)

// UDPListener gère un tunnel UDP L4 sur un port local.
//
// Un client (adresse source) a une session : un socket vers le backend, gardé tant qu'il émet. Le backend voit donc
// toujours la même source pour un même client, et peut répondre par plusieurs datagrammes, à tout moment — ce que
// demandent DNS avec EDNS, QUIC, WireGuard ou RTP, et que « un socket par datagramme, une seule réponse » ne permettait pas.
type UDPListener struct {
	route   *router.Route
	conn    *net.UDPConn
	log     *slog.Logger
	metrics *Metrics

	// Gate décide d'accepter un datagramme avant de le transmettre (false : ignoré). Elle est appelée pour
	// chaque datagramme : l'appelant met en cache sa décision par client.
	Gate func(client net.Addr) bool

	maxSessions int
	idle        time.Duration

	mu       sync.Mutex
	sessions map[string]*udpSession
	stopped  bool
	pool     *pool
}

type udpSession struct {
	client   *net.UDPAddr
	backend  *net.UDPConn
	backURL  string // backend choisi, pour le signaler en panne
	lastSeen time.Time // protégé par UDPListener.mu
}

func NewUDPListener(route *router.Route, log *slog.Logger, m *Metrics) *UDPListener {
	return &UDPListener{
		route: route, log: log, metrics: m,
		maxSessions: envLimit("GPX_STREAM_MAX_UDP_SESSIONS", DefaultMaxUDPSessions),
		idle:        udpIdle(route),
		sessions:    map[string]*udpSession{},
		pool:        newPool(route),
	}
}

// udpIdle : durée d'inactivité d'une session — idle_timeout_sec de la route, sinon GPX_STREAM_UDP_IDLE, sinon 60 s.
func udpIdle(route *router.Route) time.Duration {
	if route.IdleTimeoutSec > 0 {
		return time.Duration(route.IdleTimeoutSec) * time.Second
	}
	return time.Duration(envLimit("GPX_STREAM_UDP_IDLE", int(DefaultUDPIdle/time.Second))) * time.Second
}

func (l *UDPListener) Start() error {
	addr := addrForRoute(l.route)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	l.conn = conn
	l.log.Info("UDP stream listen", "addr", addr, "route", l.route.ID)
	go l.loop()
	return nil
}

// Stop ferme l'écouteur et toutes les sessions.
func (l *UDPListener) Stop() {
	if l.conn != nil {
		l.conn.Close()
	}
	l.mu.Lock()
	l.stopped = true
	for k, s := range l.sessions {
		s.backend.Close()
		delete(l.sessions, k)
	}
	l.mu.Unlock()
}

func (l *UDPListener) loop() {
	buf := make([]byte, 64*1024)
	var delay time.Duration
	for {
		n, clientAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if acceptBackoff(err, &delay) {
				return
			}
			continue
		}
		delay = 0
		if l.Gate != nil && !l.Gate(clientAddr) {
			continue
		}
		s := l.session(clientAddr)
		if s == nil {
			continue
		}
		// Le tampon de lecture est réutilisé au tour suivant : Write copie ses octets avant de rendre la main.
		if nw, err := s.backend.Write(buf[:n]); err == nil {
			l.metrics.BytesOut.Add(int64(nw))
		}
	}
}

// session retourne la session du client, créée au premier datagramme ; nil si le plafond est atteint ou si aucun
// backend n'est joignable (le datagramme est alors abandonné).
func (l *UDPListener) session(client *net.UDPAddr) *udpSession {
	key := client.String()
	l.mu.Lock()
	if s, ok := l.sessions[key]; ok {
		s.lastSeen = time.Now()
		l.mu.Unlock()
		return s
	}
	if l.stopped || len(l.sessions) >= l.maxSessions {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	backend := l.pool.pick()
	if backend == nil {
		return nil
	}
	upstreamAddr, err := net.ResolveUDPAddr("udp", backend.URL)
	if err != nil {
		l.log.Warn("UDP resolve failed", "backend", backend.URL, "err", err)
		return nil
	}
	conn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		l.log.Warn("UDP dial failed", "backend", backend.URL, "err", err)
		return nil
	}
	s := &udpSession{client: client, backend: conn, backURL: backend.URL, lastSeen: time.Now()}

	l.mu.Lock()
	if existing, ok := l.sessions[key]; ok { // deux datagrammes du même client ont couru l'un contre l'autre
		l.mu.Unlock()
		conn.Close()
		return existing
	}
	if l.stopped || len(l.sessions) >= l.maxSessions {
		l.mu.Unlock()
		conn.Close()
		return nil
	}
	l.sessions[key] = s
	l.mu.Unlock()
	go l.relay(key, s)
	return s
}

// relay transmet au client les datagrammes du backend jusqu'à l'inactivité de la session ou à l'arrêt.
func (l *UDPListener) relay(key string, s *udpSession) {
	buf := make([]byte, 64*1024)
	defer func() {
		s.backend.Close()
		l.mu.Lock()
		if l.sessions[key] == s {
			delete(l.sessions, key)
		}
		l.mu.Unlock()
	}()
	for {
		s.backend.SetReadDeadline(time.Now().Add(l.idle)) //nolint:errcheck
		n, err := s.backend.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				l.mu.Lock()
				active := time.Since(s.lastSeen) < l.idle
				l.mu.Unlock()
				if active {
					continue
				}
			}
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				l.mu.Lock()
				stopped := l.stopped
				l.mu.Unlock()
				if !stopped && !errors.Is(err, net.ErrClosed) {
					l.pool.markDown(s.backURL) // ICMP « port unreachable » : le backend ne répond plus
				}
			}
			return // inactive, fermée ou backend injoignable
		}
		l.mu.Lock()
		s.lastSeen = time.Now() // un backend qui parle garde la session ouverte, même si le client se tait
		l.mu.Unlock()
		if _, err := l.conn.WriteToUDP(buf[:n], s.client); err == nil {
			l.metrics.BytesIn.Add(int64(n))
		}
	}
}
