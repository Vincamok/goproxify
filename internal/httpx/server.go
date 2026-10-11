// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package httpx regroupe les réglages communs des serveurs HTTP du projet.
package httpx

import (
	"net/http"
	"time"
)

const (
	// HeaderTimeout borne la lecture des en-têtes : sans elle, un client qui les envoie un octet à la fois (slowloris)
	// garde une connexion et une goroutine ouvertes indéfiniment.
	HeaderTimeout = 10 * time.Second
	// IdleTimeout ferme une connexion persistante restée inactive : sans lui, les connexions oubliées s'accumulent
	// jusqu'à épuiser les descripteurs de fichiers.
	IdleTimeout = 120 * time.Second
)

// Harden pose les délais de connexion que le serveur ne fixe pas lui-même (un délai déjà défini est conservé), et
// retourne srv. Ni ReadTimeout ni WriteTimeout ne sont imposés : certains serveurs relaient des corps volumineux
// ou des flux.
func Harden(srv *http.Server) *http.Server {
	if srv.ReadHeaderTimeout == 0 {
		srv.ReadHeaderTimeout = HeaderTimeout
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = IdleTimeout
	}
	return srv
}
