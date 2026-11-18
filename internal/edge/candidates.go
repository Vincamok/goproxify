// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Candidats d'adresse d'un backend découvert (ADR 0026) : l'Agent propose plusieurs adresses du même conteneur (IP
// interne et port applicatif, hôte et port publié), la passerelle sert la première qu'elle joint.

const (
	maxCandidates       = 8
	candidateInterval   = 10 * time.Second
	candidateDialTimout = time.Second
	candidateParallel   = 32
	// demoteAfter : sondes ratées d'affilée avant de quitter l'adresse servie pour une moins préférée.
	demoteAfter = 2
)

// cleanCandidates garde les candidats utilisables d'un backend : sans doublon, au plus maxCandidates, et seulement quand
// la route a un backend unique (plusieurs conteneurs forment un pool, chacun garde son adresse). Moins de deux
// candidats : rien à choisir.
func cleanCandidates(in []string, backends int) []string {
	if backends != 1 || len(in) < 2 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || slices.Contains(out, c) {
			continue
		}
		out = append(out, c)
		if len(out) == maxCandidates {
			break
		}
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

// kickCandidateProbe demande une passe de sonde sans attendre le prochain tick.
func (s *Server) kickCandidateProbe() {
	select {
	case s.candidateKick <- struct{}{}:
	default:
	}
}

func (s *Server) candidateLoop(ctx context.Context) {
	t := time.NewTicker(candidateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.candidateKick:
		}
		s.probeCandidates(ctx)
	}
}

// candidateKey identifie un backend à candidats d'une route.
func candidateKey(routeID string, b router.Backend) string { return routeID + "|" + b.ContainerID }

// probeCandidates sonde tous les candidats des routes découvertes et met à jour l'adresse servie.
func (s *Server) probeCandidates(ctx context.Context) {
	type job struct {
		rt  *router.Route
		idx int
	}
	var jobs []job
	for _, rt := range s.table.All() {
		for i, b := range rt.Backends {
			if len(b.Candidates) > 1 && b.OwnerEdgeEndpoint == "" {
				jobs = append(jobs, job{rt, i})
			}
		}
	}
	if len(jobs) == 0 {
		s.candidateFails = nil
		return
	}

	reach := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, candidateParallel)
	for _, j := range jobs {
		for _, c := range j.rt.Backends[j.idx].Candidates {
			mu.Lock()
			_, done := reach[c]
			if !done {
				reach[c] = false
			}
			mu.Unlock()
			if done {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(c string) {
				defer wg.Done()
				defer func() { <-sem }()
				ok := dialCandidate(ctx, c)
				mu.Lock()
				reach[c] = ok
				mu.Unlock()
			}(c)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	fails := make(map[string]int, len(jobs))
	for _, j := range jobs {
		b := j.rt.Backends[j.idx]
		key := candidateKey(j.rt.ID, b)
		chosen, fail := chooseCandidate(b, func(c string) bool { return reach[c] }, s.candidateFails[key])
		if fail > 0 {
			fails[key] = fail
		}
		if chosen == b.URL {
			continue
		}
		cur, ok := s.table.ByID(j.rt.ID)
		if !ok || j.idx >= len(cur.Backends) || cur.Backends[j.idx].ContainerID != b.ContainerID || cur.Backends[j.idx].URL != b.URL {
			continue
		}
		next := *cur
		next.Backends = slices.Clone(cur.Backends)
		next.Backends[j.idx].URL = chosen
		s.table.Upsert(&next)
		s.log.Info("agent: adresse du backend retenue parmi les candidats", "host", cur.Host, "container", b.ContainerID, "ancienne", b.URL, "retenue", chosen)
	}
	s.candidateFails = fails
}

// chooseCandidate rend l'adresse à servir et le nombre de sondes ratées d'affilée de l'adresse actuelle. Promotion
// immédiate vers un candidat plus préféré qui répond ; rétrogradation seulement après demoteAfter échecs ; si rien ne
// répond, l'adresse actuelle est gardée.
func chooseCandidate(b router.Backend, reachable func(string) bool, fails int) (string, int) {
	best := ""
	for _, c := range b.Candidates {
		if reachable(c) {
			best = c
			break
		}
	}
	if best == "" {
		return b.URL, fails
	}
	if best == b.URL {
		return b.URL, 0
	}
	curRank, bestRank := slices.Index(b.Candidates, b.URL), slices.Index(b.Candidates, best)
	if curRank < 0 {
		// L'adresse servie n'est plus un candidat (l'Agent en propose d'autres) : rien à ménager.
		return best, 0
	}
	if reachable(b.URL) {
		if bestRank < curRank {
			return best, 0
		}
		return b.URL, 0
	}
	if fails+1 >= demoteAfter {
		return best, 0
	}
	return b.URL, fails + 1
}

// dialCandidate dit si l'adresse accepte une connexion TCP.
func dialCandidate(ctx context.Context, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	d := net.Dialer{Timeout: candidateDialTimout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
