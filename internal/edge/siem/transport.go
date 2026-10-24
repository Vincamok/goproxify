// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Sender livre un lot de lignes à un SIEM. Un lot est livré en entier ou le sender rend une erreur : l'exporteur le
// renverra tel quel (au moins une fois).
type Sender interface {
	Send(ctx context.Context, recs []Record) error
	Close()
}

const (
	dialTimeout  = 10 * time.Second
	writeTimeout = 20 * time.Second
	httpTimeout  = 30 * time.Second
)

func tlsConfig(host, caPEM string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if caPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("autorité de certification illisible")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// NewSender prépare l'envoi vers une destination.
func NewSender(d Destination) (Sender, error) {
	switch d.Type {
	case TypeSyslog:
		host, _, err := net.SplitHostPort(d.Address)
		if err != nil {
			return nil, err
		}
		var cfg *tls.Config
		if d.TLS {
			if cfg, err = tlsConfig(host, d.CAPEM); err != nil {
				return nil, err
			}
		}
		facility := 16
		if d.Facility != nil {
			facility = *d.Facility
		}
		return &syslogSender{addr: d.Address, tls: cfg, facility: facility}, nil
	case TypeHTTP, TypeOTLP:
		client := &http.Client{Timeout: httpTimeout}
		if d.CAPEM != "" {
			cfg, err := tlsConfig("", d.CAPEM)
			if err != nil {
				return nil, err
			}
			cfg.ServerName = ""
			client.Transport = &http.Transport{TLSClientConfig: cfg}
		}
		return &httpSender{url: d.Address, headers: d.Headers, client: client, otlp: d.Type == TypeOTLP}, nil
	}
	return nil, fmt.Errorf("type inconnu %q", d.Type)
}

// syslogSender écrit des messages RFC 5424 sur une connexion TCP (ou TLS), cadrés par comptage d'octets (RFC 6587).
// Un TCP qui accepte l'écriture n'a pas prouvé que le SIEM a lu : en cas de coupure en plein lot, le lot est renvoyé
// en entier, d'où les doublons possibles et l'identifiant de chaque ligne.
type syslogSender struct {
	addr     string
	tls      *tls.Config
	facility int
	conn     net.Conn
}

func (s *syslogSender) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: dialTimeout}
	if s.tls != nil {
		td := tls.Dialer{NetDialer: &d, Config: s.tls}
		conn, err := td.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return err
		}
		s.conn = conn
		return nil
	}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *syslogSender) Send(ctx context.Context, recs []Record) error {
	if s.conn == nil {
		if err := s.connect(ctx); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	for _, r := range recs {
		msg := Syslog(r, s.facility)
		buf.WriteString(strconv.Itoa(len(msg)))
		buf.WriteByte(' ')
		buf.Write(msg)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		s.Close()
		return err
	}
	return nil
}

func (s *syslogSender) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// httpSender envoie un lot de lignes par requête POST ; une réponse 2xx vaut accusé de réception. Le corps est du
// NDJSON, ou de l'OTLP/HTTP JSON pour une destination de type otlp.
type httpSender struct {
	url     string
	headers map[string]string
	client  *http.Client
	otlp    bool
}

func (h *httpSender) Send(ctx context.Context, recs []Record) error {
	var buf bytes.Buffer
	contentType := "application/x-ndjson"
	if h.otlp {
		buf.Write(OTLPBody(recs))
		contentType = "application/json"
	} else {
		for _, r := range recs {
			buf.Write(JSONLine(r))
			buf.WriteByte('\n')
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "goproxify-siem")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("réponse %d : %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}

func (h *httpSender) Close() { h.client.CloseIdleConnections() }
