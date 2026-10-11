// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// TCPListener gère un proxy TCP L4 sur un port local.
type TCPListener struct {
	route    *router.Route
	listener net.Listener
	log      *slog.Logger
	metrics  *Metrics

	// Gate, si elle est définie, décide d'accepter une connexion avant tout appel au backend : false ferme la
	// connexion. C'est le point d'accroche du hook connect des plugins.
	Gate func(client net.Addr) bool

	conns chan struct{} // jetons des connexions en cours (plafond DefaultMaxConns)
	pool  *pool
	stop  context.CancelFunc // arrête les sondes de santé
}

func NewTCPListener(route *router.Route, log *slog.Logger, m *Metrics) *TCPListener {
	return &TCPListener{route: route, log: log, metrics: m, pool: newPool(route), conns: make(chan struct{}, envLimit("GPX_STREAM_MAX_CONNS", DefaultMaxConns))}
}

func (l *TCPListener) Start() error {
	addr := addrForRoute(l.route)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	l.listener = ln
	l.log.Info("TCP stream listen", "addr", addr, "route", l.route.ID)
	if cfg := l.route.HealthCheck; cfg != nil && len(l.route.Backends) > 1 {
		ctx, cancel := context.WithCancel(context.Background())
		l.stop = cancel
		go l.pool.probe(ctx, cfg)
	}
	go l.accept()
	return nil
}

func (l *TCPListener) Stop() {
	if l.stop != nil {
		l.stop()
	}
	if l.listener != nil {
		l.listener.Close()
	}
}

func (l *TCPListener) accept() {
	var delay time.Duration
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if acceptBackoff(err, &delay) {
				return
			}
			l.log.Warn("TCP accept", "route", l.route.ID, "err", err)
			continue
		}
		delay = 0
		select {
		case l.conns <- struct{}{}:
			go func() {
				defer func() { <-l.conns }()
				l.handle(conn)
			}()
		default:
			conn.Close() // plafond atteint : refuser vaut mieux que d'épuiser les descripteurs
		}
	}
}

func (l *TCPListener) handle(client net.Conn) {
	defer client.Close()

	if l.Gate != nil && !l.Gate(client.RemoteAddr()) {
		return
	}
	upstream, _, err := l.pool.dialTCP(5 * time.Second)
	if err != nil {
		l.log.Warn("TCP dial failed", "route", l.route.ID, "backends", len(l.route.Backends), "err", err)
		return
	}
	defer upstream.Close()

	l.metrics.ActiveConnections.Add(1)
	defer l.metrics.ActiveConnections.Add(-1)

	// Inactivité : un seul minuteur pour les deux sens (un téléchargement n'envoie rien vers le serveur et ne doit
	// pas être coupé). Il est réarmé à chaque octet lu ; à l'échéance, les deux connexions sont fermées.
	var touch func()
	if d := time.Duration(l.route.IdleTimeoutSec) * time.Second; d > 0 {
		timer := time.AfterFunc(d, func() { client.Close(); upstream.Close() })
		defer timer.Stop()
		touch = func() { timer.Reset(d) }
	}

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn, toBackend bool) {
		buf := middleware.GetBuf()
		defer middleware.PutBuf(buf)
		var r io.Reader = src
		if touch != nil {
			r = touchReader{src, touch}
		}
		n, _ := io.CopyBuffer(dst, r, *buf)
		if toBackend {
			l.metrics.BytesOut.Add(n)
		} else {
			l.metrics.BytesIn.Add(n)
		}
		done <- struct{}{}
	}
	go pipe(upstream, client, true)
	go pipe(client, upstream, false)
	<-done
}
