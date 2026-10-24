// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/portainer"
	"github.com/vincamok/goproxify/internal/agent/statepub"
	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	"github.com/vincamok/goproxify/internal/edge/proxy"
)

// Maquette de bout en bout du groupe HA : un frontal et un backup, un vrai Agent Portainer branché sur un faux
// Portainer, les vraies réplications entre les deux passerelles. Elle rejoue l'incident d'origine : un backup qui
// rame, un Agent qui bascule, un backup qui redémarre, et des routes qui doivent rester servies par tout le groupe.

type fakePortainer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	down bool
	list map[string]string // identifiant de conteneur → hôte
}

func newFakePortainer(t *testing.T, containers map[string]string) *fakePortainer {
	f := &fakePortainer{list: containers}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/endpoints":
			io.WriteString(w, `[{"Id":1,"Name":"alpha","URL":"tcp://10.1.1.1:2375","Status":1}]`)
		case strings.HasPrefix(r.URL.Path, "/api/endpoints/1/docker/containers/json"):
			if f.down {
				http.Error(w, "délai dépassé", http.StatusGatewayTimeout)
				return
			}
			var items []string
			for id, host := range f.list {
				items = append(items, fmt.Sprintf(`{"Id":%q,"Names":["/%s"],"Image":"nginx","State":"running",
					"Labels":{"goproxify.enable":"true","goproxify.host":%q,"goproxify.port":"80"},
					"Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"NetworkSettings":{"Networks":{}}}`, id, host, host))
			}
			io.WriteString(w, "["+strings.Join(items, ",")+"]")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePortainer) set(down bool, list map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
	if list != nil {
		f.list = list
	}
}

// syncGroup fait faire à dst un tour de synchronisation avec src : ce que fait la passerelle toutes les 15 s.
func syncGroup(dst, src *stateNode) {
	client := &http.Client{Timeout: 3 * time.Second}
	peer := proxy.PeerInfo{Name: src.name, Endpoint: src.http.URL, Token: "tok"}
	ctx := context.Background()
	dst.srv.syncAgentStateFromPeer(ctx, client, peer)
	dst.srv.syncAgentNodesFromPeer(ctx, client, peer)
	dst.srv.syncProxiesFromPeer(ctx, client, peer)
}

func serves(n *stateNode, host string) bool {
	rt, ok := n.srv.table.ByHost(host)
	return ok && len(rt.Backends) > 0
}

func TestHAEndToEnd_PortainerIncident(t *testing.T) {
	members := []string{"frontal", "backup"}
	frontal, backup := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(frontal.haNode, backup.haNode)

	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	pt := newFakePortainer(t, map[string]string{x: "x.example.fr", y: "y.example.fr"})
	endpoint := frontal.http.URL
	var epMu sync.Mutex
	agent := portainer.NewDiscovery(portainer.NewClient(pt.srv.URL, "key"), frontal.http.URL, "tok", "goproxify.", "agent-1", 30,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil)
	agent.SetStatePublisher(statepub.New("agent-1", ""))
	agent.SetEndpointFunc(func() string { epMu.Lock(); defer epMu.Unlock(); return endpoint })
	ctx := context.Background()

	// 1. L'Agent publie à son frontal : le backup sert aussi les deux routes, sans que l'Agent lui ait parlé.
	agent.Resync(ctx)
	waitFor(t, "le frontal sert x et y", func() bool { return serves(frontal, "x.example.fr") && serves(frontal, "y.example.fr") })
	waitFor(t, "le backup sert x et y par réplication", func() bool { return serves(backup, "x.example.fr") && serves(backup, "y.example.fr") })

	// 2. Un envoi de routes de l'Admin (chaque modification d'un proxy) n'efface plus les routes Portainer, nulle part.
	for _, n := range []*stateNode{frontal, backup} {
		if err := n.srv.table.Replace(n.srv.mergePushPreservingFileProxies(nil)); err != nil {
			t.Fatal(err)
		}
		if !serves(n, "x.example.fr") || !serves(n, "y.example.fr") {
			t.Fatalf("%s a perdu des routes Portainer après un envoi de routes de l'Admin", n.name)
		}
	}

	// 3. Le Portainer rame (le backup avait des soucis de VM) : l'endpoint ne répond plus, aucune route n'est retirée.
	pt.set(true, nil)
	agent.Resync(ctx)
	time.Sleep(400 * time.Millisecond)
	if !serves(frontal, "x.example.fr") || !serves(backup, "x.example.fr") || !serves(frontal, "y.example.fr") {
		t.Fatal("un endpoint injoignable ne doit retirer aucune route, sur aucune passerelle")
	}

	// 4. L'Agent bascule vers le backup ; entre-temps y a disparu du Portainer. Le backup retire y, et le frontal, qui
	// ne parle plus à l'Agent, l'apprend du backup.
	epMu.Lock()
	endpoint = backup.http.URL
	epMu.Unlock()
	pt.set(false, map[string]string{x: "x.example.fr"})
	agent.Resync(ctx)
	waitFor(t, "le backup retire y", func() bool { return !serves(backup, "y.example.fr") && serves(backup, "x.example.fr") })
	waitFor(t, "le frontal retire y aussi", func() bool { return !serves(frontal, "y.example.fr") && serves(frontal, "x.example.fr") })

	// 5. Le backup redémarre (table vide, mêmes clés de groupe) : il retrouve ses routes auprès du frontal, sans l'Agent.
	backup2 := proxyNode(t, "backup", members)
	link(frontal.haNode, backup2.haNode)
	if serves(backup2, "x.example.fr") {
		t.Fatal("le backup redémarré part vide")
	}
	syncGroup(backup2, frontal)
	if !serves(backup2, "x.example.fr") || serves(backup2, "y.example.fr") {
		t.Fatal("le backup redémarré doit retrouver x et ne pas retrouver y")
	}

	// 6. La liste des Agents : vu par le frontal, puis par le backup ; une seule entrée côté Admin, avec le bon membre.
	frontal.srv.nodeStore.Upsert(edgeagent.NodeInfo{NodeName: "agent-1", Role: "agent", Version: "0.15.1"})
	syncGroup(backup2, frontal)
	if n, ok := backup2.srv.nodeStore.Get("agent-1"); !ok || n.ConnectedVia != "frontal" || n.Status != "online" {
		t.Fatalf("le backup voit l'Agent du frontal : %+v", n)
	}
	time.Sleep(20 * time.Millisecond)
	backup2.srv.nodeStore.Upsert(edgeagent.NodeInfo{NodeName: "agent-1", Role: "agent", Version: "0.15.1"})
	syncGroup(frontal, backup2)
	if n, _ := frontal.srv.nodeStore.Get("agent-1"); n.ConnectedVia != "backup" {
		t.Fatalf("après la bascule, le frontal sait que l'Agent est sur le backup : %+v", n)
	}

	// 7. Un proxy publié et un proxy supprimé pendant l'absence d'un membre se rattrapent.
	publishProxy(t, frontal, "p1", "app.example.fr", "http://10.0.0.1:80", time.Now().UTC())
	syncGroup(backup2, frontal)
	if !serves(backup2, "app.example.fr") {
		t.Fatal("le proxy publié sur le frontal arrive sur le backup")
	}
	if err := frontal.srv.removeFileProxy("p1", time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	syncGroup(backup2, frontal)
	if serves(backup2, "app.example.fr") {
		t.Fatal("le proxy supprimé sur le frontal disparaît du backup")
	}

}
