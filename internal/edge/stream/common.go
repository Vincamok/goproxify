// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Metrics comptabilise les octets et connexions des streams L4.
type Metrics struct {
	BytesIn           atomic.Int64
	BytesOut          atomic.Int64
	ActiveConnections atomic.Int64
}

// DefaultMaxConns borne les connexions TCP simultanées d'un écouteur (les sessions UDP ont leur plafond dans udp.go) :
// sans borne, un client qui ouvre des connexions sans fin épuise les descripteurs de fichiers et la mémoire de la
// passerelle, donc aussi le trafic HTTP. Réglable par GPX_STREAM_MAX_CONNS.
const DefaultMaxConns = 10000

func envLimit(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return def
}

// acceptBackoff attend avant de réessayer après une erreur d'Accept/Read qui n'est pas la fermeture de l'écouteur :
// « too many open files » est transitoire, et abandonner la boucle laisserait le port ouvert mais mort.
var sleepFn = time.Sleep

func acceptBackoff(err error, delay *time.Duration) (closed bool) {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if *delay == 0 {
		*delay = 5 * time.Millisecond
	} else if *delay *= 2; *delay > time.Second {
		*delay = time.Second
	}
	sleepFn(*delay)
	return false
}

func addrForRoute(r *router.Route) string {
	return fmt.Sprintf(":%d", r.ListenPort)
}

// touchReader signale chaque lecture qui a rendu des octets (réarmement du minuteur d'inactivité).
type touchReader struct {
	r     net.Conn
	touch func()
}

func (t touchReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.touch()
	}
	return n, err
}
