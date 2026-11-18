// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package hostaddr donne l'adresse IP d'un hôte désigné par un nom : l'adresse d'API d'un environnement Arcane ou d'un
// endpoint Portainer est souvent un nom de machine, et la passerelle ne le résout pas toujours.
package hostaddr

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	ttl     = time.Minute
	timeout = 3 * time.Second
)

type entry struct {
	addr     string
	ok       bool
	at       time.Time
	reported bool
}

var (
	mu     sync.Mutex
	cache  = map[string]*entry{}
	lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
)

// Resolve rend l'adresse IP de host (IPv4 de préférence), et vrai. Une IP est rendue telle quelle. Un nom qui ne se
// résout pas est rendu inchangé avec faux ; si une adresse était connue, elle est gardée plutôt que de revenir au nom.
// Le résultat est gardé une minute : le sondage de l'Agent ne fait pas une requête DNS par conteneur.
func Resolve(host string) (string, bool) {
	if host == "" || net.ParseIP(host) != nil {
		return host, true
	}
	mu.Lock()
	e := cache[host]
	if e != nil && time.Since(e.at) < ttl {
		addr, ok := e.addr, e.ok
		mu.Unlock()
		return addr, ok
	}
	mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := lookup(ctx, host)
	best := ""
	for _, a := range addrs {
		if a.IP.To4() != nil {
			best = a.IP.String()
			break
		}
		if best == "" {
			best = a.IP.String()
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if e == nil {
		e = &entry{}
		cache[host] = e
	}
	e.at = time.Now()
	switch {
	case err == nil && best != "":
		e.addr, e.ok = best, true
	case e.ok:
		// Résolution momentanément en échec : l'adresse déjà connue reste servie.
	default:
		e.addr, e.ok = host, false
	}
	return e.addr, e.ok
}

// FirstFailure dit si c'est la première fois qu'on signale que host ne se résout pas : l'appelant ne journalise
// l'avertissement qu'une fois par nom, pas à chaque sondage.
func FirstFailure(host string) bool {
	mu.Lock()
	defer mu.Unlock()
	e := cache[host]
	if e == nil || e.ok || e.reported {
		return false
	}
	e.reported = true
	return true
}

// SetLookup remplace la résolution DNS (tests) et vide le cache ; rend la fonction qui rétablit l'état précédent.
func SetLookup(fn func(ctx context.Context, host string) ([]net.IPAddr, error)) (restore func()) {
	mu.Lock()
	prev := lookup
	lookup = fn
	cache = map[string]*entry{}
	mu.Unlock()
	return func() {
		mu.Lock()
		lookup = prev
		cache = map[string]*entry{}
		mu.Unlock()
	}
}
