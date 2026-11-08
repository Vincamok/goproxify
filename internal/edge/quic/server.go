// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package quic

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vincamok/goproxify/internal/config"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

// QUICServer expose le proxy via HTTP/3 (QUIC / UDP).
type QUICServer struct {
	srv  *http3.Server
	port int
}

// Port est le port UDP sur lequel le serveur écoute (celui que l'en-tête Alt-Svc annonce) ; 0 avant le démarrage.
func (q *QUICServer) Port() int { return q.port }

// Start démarre le serveur HTTP/3 sur UDP. Sans port QUIC configuré, il suit le port HTTPS : la configuration générée au
// premier démarrage n'en contient pas, et le serveur écoutait alors sur un port éphémère, injoignable sur 443/udp.
func (q *QUICServer) Start(cfg *config.EdgeConfig, handler http.Handler, certStore *edgetls.CertStore) error {
	quicPort := cfg.Network.QUICPort
	if quicPort == 0 {
		quicPort = cfg.Network.HTTPSPort
	}
	if quicPort == 0 {
		quicPort = 443
	}
	q.port = quicPort
	addr := fmt.Sprintf("%s:%d", cfg.Network.BindAddress, quicPort)

	altSvcHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, quicPort))
		handler.ServeHTTP(w, r)
	})

	tlsCfg := &tls.Config{
		GetCertificate: certStore.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{"h3"},
	}

	q.srv = &http3.Server{
		Addr:           addr,
		Handler:        altSvcHandler,
		TLSConfig:      tlsCfg,
		QUICConfig:     quicConfig(cfg),
		MaxHeaderBytes: cfg.MaxHeaderBytes(),
	}

	go func() {
		if err := q.srv.ListenAndServe(); err != nil {
			_ = err
		}
	}()
	return nil
}

// quicConfig construit la configuration QUIC à partir des timeouts EdgeConfig.
// HandshakeIdleTimeout ≈ ReadHeaderTimeout, MaxIdleTimeout ≈ IdleTimeout.
func quicConfig(cfg *config.EdgeConfig) *quic.Config {
	handshake := durationOrDefault(cfg.Timeouts.ReadHeaderSeconds, 10)
	idle := durationOrDefault(cfg.Timeouts.IdleSeconds, 120)
	return &quic.Config{
		HandshakeIdleTimeout: handshake,
		MaxIdleTimeout:       idle,
		MaxIncomingStreams:   1024,
	}
}

func durationOrDefault(seconds, defaultSeconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(defaultSeconds) * time.Second
}

// Stop arrête proprement le serveur HTTP/3.
func (q *QUICServer) Stop() {
	if q.srv != nil {
		q.srv.Close() //nolint:errcheck
	}
}
