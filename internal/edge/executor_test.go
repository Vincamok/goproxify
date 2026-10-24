// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"strings"

	"github.com/vincamok/goproxify/internal/config"

	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"net/http"
	"sync"
	"testing"
	"time"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

type ruleSink struct {
	mu  sync.Mutex
	got []edgews.RuleFiredPayload
}

func (r *ruleSink) hook(p edgews.RuleFiredPayload) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, p)
}

func (r *ruleSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// executorPair : deux membres, la fiche désigne "frontal" (identifiant le plus bas) comme premier de la liste.
func executorPair(t *testing.T) (a, b *stateNode, sa, sb *ruleSink) {
	t.Helper()
	members := []string{"frontal", "backup"}
	a, b = pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	for _, n := range []*stateNode{a, b} {
		n.http.Config.Handler.(*http.ServeMux).HandleFunc("POST "+groupRuleFiredPath, n.srv.handleGroupRuleFired)
		if err := n.srv.applyGroupCard(card(1, "ha-1")); err != nil {
			t.Fatal(err)
		}
	}
	link(a.haNode, b.haNode)
	sa, sb = &ruleSink{}, &ruleSink{}
	a.srv.ruleReportHook, b.srv.ruleReportHook = sa.hook, sb.hook
	return a, b, sa, sb
}

func notifyFiring(rule, node string) edgews.RuleFiredPayload {
	return edgews.RuleFiredPayload{NodeName: node, RuleID: rule, RuleName: rule, ActionType: "notify", CondResult: true, ActionTaken: true}
}

// Le premier membre de la fiche vu vivant est l'exécutant ; s'il ne répond plus depuis un moment, c'est le suivant.
func TestExecutorIsTheFirstLiveMemberOfTheCard(t *testing.T) {
	a, b, _, _ := executorPair(t)
	now := time.Now()

	if _, self := a.srv.groupExecutor(now); !self {
		t.Fatal("frontal est le premier de la fiche : il est l'exécutant")
	}
	if _, self := b.srv.groupExecutor(now); !self {
		t.Fatal("backup n'a pas vu frontal vivant : il est son propre exécutant")
	}
	b.srv.peerSeen.mark("frontal", now)
	exec, self := b.srv.groupExecutor(now)
	if self || exec.Name != "frontal" {
		t.Fatalf("backup voit frontal vivant : l'exécutant est frontal, pas lui (%+v self=%v)", exec, self)
	}
	if _, self := b.srv.groupExecutor(now.Add(peerAliveFor + time.Second)); !self {
		t.Fatal("frontal n'a pas répondu depuis plus de 45 s : backup devient l'exécutant")
	}
}

// Sans fiche ni groupe connu, un membre est son propre exécutant.
func TestExecutorWithoutGroupIsSelf(t *testing.T) {
	s := &Server{cfg: &config.EdgeConfig{}}
	if _, self := s.groupExecutor(time.Now()); !self {
		t.Fatal("seul : exécutant")
	}
}

// Un même incident vu par les deux membres remonte une seule fois, quel que soit celui qui le voit en premier ; une alerte
// que seul le non-exécutant voit n'est pas perdue.
func TestNotificationFiringIsReportedOnceByTheExecutor(t *testing.T) {
	a, b, sa, sb := executorPair(t)
	b.srv.peerSeen.mark("frontal", time.Now())
	a.srv.peerSeen.mark("backup", time.Now())

	b.srv.onRuleFired(ruleFired("r1", "notify"))
	a.srv.onRuleFired(ruleFired("r1", "notify"))
	if sa.count() != 1 || sb.count() != 0 {
		t.Fatalf("l'exécutant remonte une fois, le non-exécutant jamais : frontal=%d backup=%d", sa.count(), sb.count())
	}
	if got := sa.got[0]; got.NodeName != "backup" {
		t.Fatalf("le déclenchement garde le membre qui l'a vu : %+v", got)
	}

	// Une autre règle n'est pas un doublon.
	b.srv.onRuleFired(ruleFired("r2", "notify"))
	if sa.count() != 2 {
		t.Fatalf("une autre règle remonte : %d", sa.count())
	}
}

// Si l'exécutant ne répond pas, le membre qui a vu l'incident le remonte lui-même.
func TestNotificationFiringFallsBackWhenTheExecutorIsUnreachable(t *testing.T) {
	a, b, sa, sb := executorPair(t)
	b.srv.peerSeen.mark("frontal", time.Now())
	a.http.Close() // frontal est tombé alors qu'il paraissait vivant

	b.srv.onRuleFired(ruleFired("r1", "notify"))
	if sb.count() != 1 || sa.count() != 0 {
		t.Fatalf("backup remonte lui-même : frontal=%d backup=%d", sa.count(), sb.count())
	}
}

// Seules les notifications passent par l'exécutant : un ban, une désactivation de proxy ou un déclenchement en sourdine
// remontent depuis le membre qui les a vus.
func TestOtherFiringsStayLocal(t *testing.T) {
	_, b, sa, sb := executorPair(t)
	b.srv.peerSeen.mark("frontal", time.Now())

	b.srv.onRuleFired(ruleFired("r1", "ban_ip"))
	silenced := ruleFired("r2", "notify")
	silenced.Silenced = true
	b.srv.onRuleFired(silenced)
	if sb.count() != 2 || sa.count() != 0 {
		t.Fatalf("remontés localement : backup=%d frontal=%d", sb.count(), sa.count())
	}
}

// Un déclenchement qui n'est pas une notification, ou un corps qui n'est pas chiffré par la clé du groupe, est refusé.
func TestGroupRuleFiredRefusesForeignBodies(t *testing.T) {
	a, _, sa, _ := executorPair(t)
	resp, err := http.Post(a.http.URL+groupRuleFiredPath, "application/octet-stream", stringsReader("pas chiffré"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || sa.count() != 0 {
		t.Fatalf("corps en clair refusé : %d, remontés %d", resp.StatusCode, sa.count())
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

func ruleFired(rule, action string) edgere.ExecLog {
	return edgere.ExecLog{RuleID: rule, RuleName: rule, ActionType: action, CondResult: true, ActionTaken: true, FiredAt: time.Now()}
}
