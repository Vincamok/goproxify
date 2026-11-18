// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestDirectorySourceOf(t *testing.T) {
	for name, tc := range map[string]struct {
		ids  []string
		want string
	}{
		"docker":         {[]string{"0123456789ab0123456789ab"}, ""},
		"kubernetes":     {[]string{"k8s:ns/app"}, ""},
		"arcane":         {[]string{"3f2a9c1d00000000000000000000abcd@arcane"}, "arcane"},
		"consul":         {[]string{"abc@consul"}, "consul"},
		"aucun":          {nil, ""},
		"nom invalide":   {[]string{"abc@Bad Name"}, ""},
		"premier trouvé": {[]string{"deadbeef", "abc@nomad"}, "nomad"},
	} {
		if got := directorySourceOf(tc.ids); got != tc.want {
			t.Errorf("%s : %q, attendu %q", name, got, tc.want)
		}
	}
}

func arcaneRoute(host, cid, backend string) map[string]any {
	return map[string]any{
		"host": host, "backends": []string{backend},
		"source": "arcane", "container_id": cid, "agent_name": "ag",
	}
}

// Un conteneur d'Arcane redémarré garde son identifiant et change de port publié : la route doit suivre le nouveau
// backend sans en garder l'ancien.
func TestAgentStateArcaneBackendFollowsPortChange(t *testing.T) {
	s := testEdgeServer()
	const cid = "3f2a9c1d00000000000000000000abcd@arcane"
	if code, _ := putState(t, s, state("arcane", "", 1, arcaneRoute("app.example.fr", cid, "http://10.0.0.5:32788"))); code != 200 {
		t.Fatalf("premier état : %d", code)
	}
	if code, _ := putState(t, s, state("arcane", "", 2, arcaneRoute("app.example.fr", cid, "http://10.0.0.5:32768"))); code != 200 {
		t.Fatalf("second état : %d", code)
	}
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok || len(rt.Backends) != 1 || rt.Backends[0].URL != "http://10.0.0.5:32768" {
		t.Fatalf("le backend doit passer au nouveau port : %+v", rt)
	}
}

func listenLocal(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String(), func() { l.Close() }
}

func closedAddr(t *testing.T) string {
	t.Helper()
	addr, closeFn := listenLocal(t)
	closeFn()
	return addr
}

func candidateRoute(host, cid string, backend string, candidates ...string) *agentContainerPayload {
	return &agentContainerPayload{Host: host, Backends: []string{backend}, Candidates: candidates, Source: "arcane", ContainerID: cid, AgentName: "ag"}
}

func servedURL(t *testing.T, s *Server, host string) string {
	t.Helper()
	rt, ok := s.table.ByHost(host)
	if !ok || len(rt.Backends) != 1 {
		t.Fatalf("route %s : %+v", host, rt)
	}
	return rt.Backends[0].URL
}

func TestChooseCandidate(t *testing.T) {
	reach := func(ok ...string) func(string) bool {
		return func(c string) bool { return slices.Contains(ok, c) }
	}
	b := router.Backend{URL: "http://pub", Candidates: []string{"http://int", "http://pub"}}
	for name, tc := range map[string]struct {
		b     router.Backend
		reach func(string) bool
		fails int
		want  string
		wantF int
	}{
		"promotion immédiate":              {b, reach("http://int", "http://pub"), 0, "http://int", 0},
		"servie et préférée":               {router.Backend{URL: "http://int", Candidates: b.Candidates}, reach("http://int", "http://pub"), 0, "http://int", 0},
		"rien ne répond, on garde":         {b, reach(), 0, "http://pub", 0},
		"servie coupée, première sonde":    {router.Backend{URL: "http://int", Candidates: b.Candidates}, reach("http://pub"), 0, "http://int", 1},
		"servie coupée, seconde sonde":     {router.Backend{URL: "http://int", Candidates: b.Candidates}, reach("http://pub"), 1, "http://pub", 0},
		"servie répond, moins préférée ok": {b, reach("http://pub"), 0, "http://pub", 0},
		"adresse servie hors liste":        {router.Backend{URL: "http://autre", Candidates: b.Candidates}, reach("http://int"), 0, "http://int", 0},
	} {
		got, f := chooseCandidate(tc.b, tc.reach, tc.fails)
		if got != tc.want || f != tc.wantF {
			t.Errorf("%s : %q (%d échecs), attendu %q (%d)", name, got, f, tc.want, tc.wantF)
		}
	}
}

func TestCleanCandidates(t *testing.T) {
	if got := cleanCandidates([]string{"http://a", "http://b", "http://a", " "}, 1); !slices.Equal(got, []string{"http://a", "http://b"}) {
		t.Errorf("doublons et vides retirés : %v", got)
	}
	if cleanCandidates([]string{"http://a", "http://b"}, 2) != nil {
		t.Error("un pool de plusieurs backends n'a pas de candidats")
	}
	if cleanCandidates([]string{"http://a"}, 1) != nil || cleanCandidates([]string{"http://a", "http://a"}, 1) != nil {
		t.Error("un seul candidat : rien à choisir")
	}
	many := make([]string, 20)
	for i := range many {
		many[i] = "http://h" + strconv.Itoa(i)
	}
	if got := cleanCandidates(many, 1); len(got) != maxCandidates {
		t.Errorf("%d candidats gardés, %d au plus", len(got), maxCandidates)
	}
}

// L'adresse interne répond : elle est servie à la place de l'adresse publiée, et le choix survit à une réannonce de
// l'Agent.
func TestProbeCandidatesPromotesTheReachableInternalAddress(t *testing.T) {
	s := testEdgeServer()
	internal, closeInternal := listenLocal(t)
	defer closeInternal()
	published, closePub := listenLocal(t)
	defer closePub()
	in, pub := "http://"+internal, "http://"+published

	if st, _ := s.applyAgentRoute(candidateRoute("app.example.com", "c1@arcane", pub, in, pub)); st != http.StatusNoContent {
		t.Fatalf("route : %d", st)
	}
	if got := servedURL(t, s, "app.example.com"); got != pub {
		t.Fatalf("avant sonde, l'adresse sûre est servie : %q", got)
	}
	s.probeCandidates(context.Background())
	if got := servedURL(t, s, "app.example.com"); got != in {
		t.Fatalf("l'adresse interne répond, elle est servie : %q", got)
	}

	// L'Agent republie la même route : le choix de la sonde n'est pas écrasé.
	s.applyAgentRoute(candidateRoute("app.example.com", "c1@arcane", pub, in, pub))
	if got := servedURL(t, s, "app.example.com"); got != in {
		t.Fatalf("la réannonce ne doit pas défaire le choix : %q", got)
	}

	// L'adresse interne tombe : deux sondes ratées avant de revenir à l'adresse publiée.
	closeInternal()
	s.probeCandidates(context.Background())
	if got := servedURL(t, s, "app.example.com"); got != in {
		t.Fatalf("une seule sonde ratée ne change rien : %q", got)
	}
	s.probeCandidates(context.Background())
	if got := servedURL(t, s, "app.example.com"); got != pub {
		t.Fatalf("deux sondes ratées : retour à l'adresse publiée, obtenu %q", got)
	}
}

func TestProbeCandidatesKeepsTheAddressWhenNothingAnswers(t *testing.T) {
	s := testEdgeServer()
	a, b := "http://"+closedAddr(t), "http://"+closedAddr(t)
	s.applyAgentRoute(candidateRoute("down.example.com", "c2@arcane", b, a, b))
	for i := 0; i < 3; i++ {
		s.probeCandidates(context.Background())
	}
	if got := servedURL(t, s, "down.example.com"); got != b {
		t.Fatalf("aucun candidat ne répond, l'adresse sûre est gardée : %q", got)
	}
}
