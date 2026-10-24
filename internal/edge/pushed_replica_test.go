// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func pushedNode(t *testing.T, name string, members []string) *stateNode {
	t.Helper()
	t.Setenv("GPX_PUSHED_JOURNAL_PATH", filepath.Join(t.TempDir(), "pushed-journal.gpx"))
	n := proxyNode(t, name, members)
	n.http.Config.Handler.(*http.ServeMux).HandleFunc("GET "+pushedReplicaPath, n.srv.handlePushedReplicaExport)
	return n
}

func adminPush(t *testing.T, n *stateNode, typ string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.srv.handleWSAdminMessage("admin", edgews.Message{Type: typ, Payload: b}); err != nil {
		t.Fatal(err)
	}
}

func pullPushed(t *testing.T, from, to *stateNode) {
	t.Helper()
	to.srv.syncPushedFromPeer(context.Background(), &http.Client{Timeout: 3 * time.Second},
		proxy.PeerInfo{Name: from.name, Endpoint: from.http.URL, Token: "tok"})
}

func snippetNames(n *stateNode) map[string]bool {
	out := map[string]bool{}
	for _, sn := range n.srv.snippetStore.All() {
		out[sn.Name] = true
	}
	return out
}

func snippetsPush(names ...string) []*router.Snippet {
	var list []*router.Snippet
	for _, nm := range names {
		list = append(list, &router.Snippet{ID: nm, Name: nm, Type: router.SnippetType("headers"), Config: json.RawMessage(`{}`)})
	}
	return list
}

// Une passerelle absente au moment de la poussée de l'Admin rattrape le document auprès de son pair, sans l'Admin.
func TestPushedConfigCatchesUpAMemberThatMissedAPush(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)

	adminPush(t, a, edgews.TypePushSnippets, snippetsPush("s1", "s2"))
	if len(snippetNames(b)) != 0 {
		t.Fatal("B n'a rien reçu de l'Admin")
	}
	pullPushed(t, a, b)
	got := snippetNames(b)
	if !got["s1"] || !got["s2"] {
		t.Fatalf("B doit avoir rattrapé les snippets de A : %v", got)
	}
}

// Quand l'Admin a poussé les deux membres, rien ne se rejoue : la date de réception diffère de quelques millisecondes
// mais le contenu est le même.
func TestPushedConfigIsNotReappliedWhenContentMatches(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)
	adminPush(t, a, edgews.TypePushSnippets, snippetsPush("s1"))
	adminPush(t, b, edgews.TypePushSnippets, snippetsPush("s1"))

	if a.srv.adminDocs.doc().digest() != b.srv.adminDocs.doc().digest() {
		t.Fatal("même contenu, même condensé")
	}
	doc := a.srv.adminDocs.doc()
	if n := b.srv.mergePushedReplica(doc, "frontal"); n != 0 {
		t.Fatalf("rien à appliquer, %d appliqué(s)", n)
	}
}

// Le document le plus récent gagne, dans les deux sens : un pair en retard n'écrase pas un membre à jour.
func TestPushedConfigNewestWins(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)

	adminPush(t, a, edgews.TypePushSnippets, snippetsPush("ancien"))
	time.Sleep(5 * time.Millisecond)
	adminPush(t, b, edgews.TypePushSnippets, snippetsPush("recent"))

	pullPushed(t, a, b) // A est en retard
	if got := snippetNames(b); !got["recent"] || got["ancien"] {
		t.Fatalf("B garde sa version plus récente : %v", got)
	}
	pullPushed(t, b, a)
	if got := snippetNames(a); !got["recent"] || got["ancien"] {
		t.Fatalf("A adopte la version plus récente de B : %v", got)
	}
}

// Les certificats sont retenus par nom : deux certificats ne s'écrasent pas, et la clé privée ne circule qu'avec le
// document chiffré par la clé du groupe.
func TestPushedCertificatesAreKeptPerName(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := pushedNode(t, "frontal", members)
	if got := pushedKey(edgews.TypePushCert, json.RawMessage(`{"name":"a.example.fr"}`)); got != edgews.TypePushCert+"|a.example.fr" {
		t.Fatalf("clé de certificat : %q", got)
	}
	a.srv.journalPushed(edgews.TypePushCert, json.RawMessage(`{"name":"a.example.fr"}`), time.Now())
	a.srv.journalPushed(edgews.TypePushCert, json.RawMessage(`{"name":"b.example.fr"}`), time.Now())
	if n := len(a.srv.adminDocs.doc().Entries); n != 2 {
		t.Fatalf("deux certificats attendus, %d", n)
	}
}

// Un pair ne peut pas faire appliquer autre chose que les documents de configuration prévus (jeton Admin, pairs,
// routes...), ni un document dont le contenu ne correspond pas à son condensé.
func TestPushedReplicaRefusesForeignTypesAndTamperedEntries(t *testing.T) {
	members := []string{"frontal", "backup"}
	b := pushedNode(t, "backup", members)
	payload := json.RawMessage(`{"token":"pirate"}`)
	forged := pushedDoc{Entries: []pushedEntry{
		{Key: edgews.TypeAdminToken, Type: edgews.TypeAdminToken, Payload: payload, At: time.Now().Add(time.Hour), Hash: pushedHash(payload)},
		{Key: edgews.TypePushSnippets, Type: edgews.TypePushSnippets, Payload: json.RawMessage(`[]`), At: time.Now().Add(time.Hour), Hash: "pas-le-bon"},
		{Key: edgews.TypePushRoutes, Type: edgews.TypePushRoutes, Payload: json.RawMessage(`[]`), At: time.Now().Add(time.Hour), Hash: pushedHash(json.RawMessage(`[]`))},
	}}
	if n := b.srv.mergePushedReplica(forged, "frontal"); n != 0 {
		t.Fatalf("rien ne doit être appliqué, %d appliqué(s)", n)
	}
	if len(b.srv.adminDocs.doc().Entries) != 0 {
		t.Fatal("le journal reste vide")
	}
}

// Un membre qui redémarre pendant la coupure de l'Admin retrouve son journal : il garde la date de sa version et ne
// se laisse pas écraser par un pair plus ancien.
func TestPushedJournalSurvivesARestart(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := pushedNode(t, "frontal", members)
	adminPush(t, a, edgews.TypePushSnippets, snippetsPush("s1"))
	want := a.srv.adminDocs.doc()

	restarted := &Server{cfg: a.srv.cfg, log: a.srv.log, cache: a.srv.cache}
	restarted.loadPushedJournalFromDisk()
	got := restarted.adminDocs.doc()
	if len(got.Entries) != 1 || got.Entries[0].At != want.Entries[0].At || got.digest() != want.digest() {
		t.Fatalf("journal relu : %+v, attendu %+v", got, want)
	}
}

// Sans clé de groupe, rien n'est servi.
func TestPushedReplicaNeedsGroupKey(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handlePushedReplicaExport(rec, httptest.NewRequest(http.MethodGet, pushedReplicaPath, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("204 attendu, %d", rec.Code)
	}
}
