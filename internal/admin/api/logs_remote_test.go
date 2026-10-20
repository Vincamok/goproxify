package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

func node(id, name string) edgeproxy.Target { return edgeproxy.Target{ID: id, NodeName: name} }

// resp fabrique la réponse d'une passerelle : n lignes d'accès de la plus récente (ts = hi) à la plus ancienne.
func resp(kind string, startID int64, tsList ...string) *logapi.SearchResponse {
	r := &logapi.SearchResponse{}
	for i, ts := range tsList {
		r.Entries = append(r.Entries, logapi.Entry{ID: startID - int64(i), Kind: kind, Ts: ts, Path: fmt.Sprintf("/%s-%d", ts[len(ts)-9:len(ts)-1], startID-int64(i))})
	}
	return r
}

func ts(sec int) string { return fmt.Sprintf("2026-10-21T10:00:%02d.000000Z", sec) }

func paths(p mergedPage) []string {
	out := make([]string, len(p.Entries))
	for i, e := range p.Entries {
		out[i] = e.Ts[17:19] + "@" + e.NodeName
	}
	return out
}

func TestMergeSearchOrdersByTimeAcrossGateways(t *testing.T) {
	a := nodeResult{T: node("id-a", "gw-a"), Resp: resp("access", 30, ts(9), ts(5), ts(1))}
	b := nodeResult{T: node("id-b", "gw-b"), Resp: resp("access", 20, ts(8), ts(5), ts(2))}
	got := paths(mergeSearch([]nodeResult{b, a}, nil, 10))
	want := []string{"09@gw-a", "08@gw-b", "05@gw-a", "05@gw-b", "02@gw-b", "01@gw-a"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ordre = %v, attendu %v", got, want)
	}
}

// Le jeton place chaque passerelle juste après la dernière ligne retenue, pas après la dernière rendue : les
// lignes rendues mais non retenues reviennent à la page suivante.
func TestMergeSearchCursorFollowsWhatWasKeptNotWhatWasReturned(t *testing.T) {
	a := resp("access", 30, ts(9), ts(8), ts(7), ts(6))
	a.HasMore = true
	b := resp("access", 20, ts(5), ts(4), ts(3), ts(2))
	b.HasMore = true
	page := mergeSearch([]nodeResult{{T: node("id-a", "gw-a"), Resp: a}, {T: node("id-b", "gw-b"), Resp: b}}, nil, 3)
	if got := paths(page); fmt.Sprint(got) != "[09@gw-a 08@gw-a 07@gw-a]" || !page.HasMore {
		t.Fatalf("page = %v has_more=%v", got, page.HasMore)
	}
	cur, err := decodeRemoteCursor(page.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	posA, _ := logapi.DecodeCursor(cur["id-a"])
	if posA["access"].Ts != ts(7) || posA["access"].ID != 28 {
		t.Fatalf("position de gw-a = %+v, attendu la ligne 07 (id 28)", posA)
	}
	// gw-b n'a rien fourni à cette page : sa position reste celle d'avant (aucune).
	if cur["id-b"] != "" {
		t.Fatalf("gw-b n'a rien fourni, son jeton doit rester vide : %q", cur["id-b"])
	}
}

func TestMergeSearchKeepsAUnreachableGatewayPositionAndReportsIt(t *testing.T) {
	prevB := logapi.EncodeCursor(map[string]logapi.Pos{"access": {Ts: ts(3), ID: 11}})
	prev := map[string]string{"id-b": prevB}
	good := nodeResult{T: node("id-a", "gw-a"), Resp: resp("access", 30, ts(9))}
	down := nodeResult{T: node("id-b", "gw-b"), Err: errors.New("connexion refusée")}
	page := mergeSearch([]nodeResult{good, down}, prev, 10)
	if len(page.Unreachable) != 1 || page.Unreachable[0].NodeName != "gw-b" || page.Unreachable[0].Error == "" {
		t.Fatalf("injoignables = %+v", page.Unreachable)
	}
	cur, _ := decodeRemoteCursor(page.Cursor)
	if cur["id-b"] != prevB {
		t.Fatal("la position d'une passerelle injoignable doit être conservée pour la page suivante")
	}
	if len(page.Entries) != 1 {
		t.Fatalf("%d lignes, attendu celles de la passerelle joignable", len(page.Entries))
	}
}

func TestMergeSearchPropagatesPartialAndHasMore(t *testing.T) {
	r := resp("access", 5, ts(1))
	r.Partial, r.HasMore = true, true
	page := mergeSearch([]nodeResult{{T: node("id-a", "gw-a"), Resp: r}}, nil, 10)
	if !page.Partial || !page.HasMore {
		t.Fatalf("partial=%v has_more=%v, attendu vrais", page.Partial, page.HasMore)
	}
	empty := mergeSearch(nil, nil, 10)
	if empty.HasMore || len(empty.Entries) != 0 || empty.Entries == nil {
		t.Fatalf("page vide = %+v", empty)
	}
}

func TestRemoteRefRoundTripAndValidation(t *testing.T) {
	node, kind, id, err := parseRemoteRef(remoteRef("11111111-2222", "system", 42))
	if err != nil || node != "11111111-2222" || kind != "system" || id != 42 {
		t.Fatalf("aller-retour = %q %q %d %v", node, kind, id, err)
	}
	for _, bad := range []string{"", "a:b", "a:access:x", "a:autre:1", "a:access:0", "a:access:-3", "a:b:c:d"} {
		if _, _, _, err := parseRemoteRef(bad); err == nil {
			t.Errorf("référence %q acceptée", bad)
		}
	}
}

func TestRemoteCursorRejectsGarbage(t *testing.T) {
	if _, err := decodeRemoteCursor("!!!"); err == nil {
		t.Error("jeton illisible accepté")
	}
	if m, err := decodeRemoteCursor(""); err != nil || len(m) != 0 {
		t.Errorf("jeton vide = %v, %v", m, err)
	}
}
