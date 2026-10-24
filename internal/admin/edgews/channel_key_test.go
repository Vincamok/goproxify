// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/pairing"
	"nhooyr.io/websocket"
)

func keysOf(vals []string) []pairing.Key {
	out := make([]pairing.Key, 0, len(vals))
	for _, v := range vals {
		out = append(out, pairing.Key{Value: v})
	}
	return out
}

// fakeEdge accepte une connexion signée par l'une des clés données, comme le Hub d'une passerelle.
func fakeEdge(t *testing.T, accepted ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var ok atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := edgeWS.ValidateAdminHMACKeys(r, keysOf(accepted)); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ok.Add(1)
		_, _, _ = conn.Read(r.Context()) // jusqu'à ce que l'Admin ferme
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}))
	t.Cleanup(srv.Close)
	return srv, &ok
}

func dialTo(t *testing.T, srv *httptest.Server, root, id string) (*Client, error) {
	t.Helper()
	c := &Client{edgeID: id, endpoint: srv.URL, secret: root, log: slog.Default()}
	c.ctx, c.cancel = context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(c.cancel)
	conn, err := c.dial("ws" + srv.URL[4:] + wsPath)
	if err == nil {
		t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
	}
	return c, err
}

// accepted attend que la passerelle simulée ait compté sa connexion : le serveur l'enregistre après la réponse 101, que le
// client reçoit avant.
func accepted(ok *atomic.Int32, want int32) int32 {
	deadline := time.Now().Add(time.Second)
	for ok.Load() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return ok.Load()
}

const rootSecret = "le-secret-racine-0123456789"

// Une passerelle qui n'a que sa clé dérivée accepte l'Admin sans que celui-ci lui présente la racine.
func TestAdminSignsWithTheEdgeChannelKey(t *testing.T) {
	srv, ok := fakeEdge(t, pairing.EdgeChannelKey(rootSecret, "dn_frontal"))
	c, err := dialTo(t, srv, rootSecret, "dn_frontal")
	if err != nil || accepted(ok, 1) != 1 || (c.lastKind.Load() == signKindRoot) {
		t.Fatalf("connexion par la clé dérivée : err=%v acceptées=%d racine=%v", err, ok.Load(), (c.lastKind.Load() == signKindRoot))
	}
}

// Une passerelle qui n'a pas encore la clé dérivée n'accepte que la racine : repli sur la racine.
func TestAdminFallsBackToTheRootForAnOlderEdge(t *testing.T) {
	srv, ok := fakeEdge(t, rootSecret)
	c, err := dialTo(t, srv, rootSecret, "dn_frontal")
	if err != nil || accepted(ok, 1) != 1 || !(c.lastKind.Load() == signKindRoot) {
		t.Fatalf("repli sur la racine : err=%v acceptées=%d racine=%v", err, ok.Load(), (c.lastKind.Load() == signKindRoot))
	}
	// À la reconnexion, la clé dérivée est de nouveau essayée en premier : une passerelle migrée entre-temps n'est pas
	// masquée par le repli précédent.
	if first := c.signers()[0]; first.kind == signKindRoot {
		t.Fatal("la clé dérivée passe toujours avant la racine")
	}
}

// GPX_EDGE_CHANNEL_ROOT_FALLBACK=false : jamais la racine auprès d'une passerelle.
func TestAdminNeverSendsTheRootWhenFallbackIsOff(t *testing.T) {
	t.Setenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK", "false")
	srv, ok := fakeEdge(t, rootSecret)
	if _, err := dialTo(t, srv, rootSecret, "dn_frontal"); err == nil || ok.Load() != 0 {
		t.Fatalf("la racine ne doit pas être présentée : err=%v acceptées=%d", err, accepted(ok, 1))
	}
}

// La clé dérivée d'une passerelle ne vaut pas pour une autre : une passerelle compromise ne parle pas à la place de l'Admin.
func TestAnotherEdgesChannelKeyIsRefused(t *testing.T) {
	t.Setenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK", "false")
	srv, ok := fakeEdge(t, pairing.EdgeChannelKey(rootSecret, "dn_backup"))
	if _, err := dialTo(t, srv, rootSecret, "dn_frontal"); err == nil || ok.Load() != 0 {
		t.Fatalf("la clé de backup ne valide pas frontal : err=%v acceptées=%d", err, accepted(ok, 1))
	}
}

// Une passerelle qui répond autre chose qu'un refus de signature n'est pas rejouée avec la racine.
func TestNoRootRetryOnANonAuthFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "en panne", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	if _, err := dialTo(t, srv, rootSecret, "dn_frontal"); err == nil || calls.Load() != 1 {
		t.Fatalf("un 502 n'est pas un refus de signature : err=%v appels=%d", err, calls.Load())
	}
}

// La clé d'une passerelle se calcule de son identifiant : un renommage ne la change pas, et l'identifiant se retrouve par
// le nom comme par lui-même.
func TestEdgeIDOfResolvesIDOrName(t *testing.T) {
	m := &Manager{edges: map[string]*edgeEntry{
		"dn_a": {id: "dn_a", nodeName: "frontal"},
		"dn_b": {id: "dn_b", nodeName: "backup"},
	}}
	for ref, want := range map[string]string{"dn_a": "dn_a", "frontal": "dn_a", "backup": "dn_b"} {
		if got, ok := m.EdgeIDOf(ref); !ok || got != want {
			t.Errorf("%q → %q (%v), attendu %q", ref, got, ok, want)
		}
	}
	if _, ok := m.EdgeIDOf("inconnue"); ok {
		t.Fatal("une passerelle inconnue n'a pas d'identifiant")
	}
	if pairing.EdgeChannelKey(rootSecret, "dn_a") == pairing.EdgeChannelKey(rootSecret, "dn_b") {
		t.Fatal("deux identifiants, deux clés")
	}
}

// Pendant une rotation du secret racine, l'Admin signe d'abord avec le nouveau secret, puis avec l'ancien : une passerelle qui
// n'a pas encore la nouvelle clé de canal reste atteignable, et le repli est signalé par ce qui a validé la connexion.
func TestAdminSignsWithThePreviousSecretDuringARotation(t *testing.T) {
	t.Setenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK", "false")
	oldRoot, newRoot := "ancien-secret-racine-0123456789", "nouveau-secret-racine-0123456789"
	roots := func() []pairing.Key {
		return []pairing.Key{{Value: newRoot}, {Value: oldRoot, Previous: true}}
	}
	dial := func(srv *httptest.Server) *Client {
		c := &Client{edgeID: "dn_a", endpoint: srv.URL, secret: newRoot, rootKeys: roots, log: slog.Default()}
		c.ctx, c.cancel = context.WithTimeout(context.Background(), 5*time.Second)
		t.Cleanup(c.cancel)
		conn, err := c.dial("ws" + srv.URL[4:] + wsPath)
		if err != nil {
			t.Fatalf("connexion : %v", err)
		}
		t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
		return c
	}

	// Passerelle déjà à jour : la clé du nouveau secret suffit.
	srv, _ := fakeEdge(t, pairing.EdgeChannelKey(newRoot, "dn_a"))
	if c := dial(srv); c.lastKind.Load() != signKindCurrent {
		t.Fatalf("clé courante attendue, reçu %d", c.lastKind.Load())
	}
	// Passerelle pas encore à jour : seule la clé de l'ancien secret la valide.
	srv, _ = fakeEdge(t, pairing.EdgeChannelKey(oldRoot, "dn_a"))
	if c := dial(srv); c.lastKind.Load() != signKindPrevious {
		t.Fatalf("clé précédente attendue, reçu %d", c.lastKind.Load())
	}
	// Même avec le repli sur la racine interdit, la clé dérivée de l'ancien secret passe : ce n'est pas la racine.
	if len((&Client{edgeID: "dn_a", secret: newRoot, rootKeys: roots}).signers()) != 2 {
		t.Fatal("deux clés dérivées, aucune racine brute")
	}
}

// Un déploiement qui ne connaît pas l'identifiant que l'Admin attribue (Helm, démarrage rapide) dérive la clé du nom de la
// passerelle : l'Admin l'essaie après celle de l'identifiant, sans jamais présenter la racine.
func TestAdminSignsWithTheNameDerivedKeyWhenTheIDKeyIsRefused(t *testing.T) {
	t.Setenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK", "false")
	srv, ok := fakeEdge(t, pairing.EdgeChannelKey(rootSecret, "goproxify-edge"))
	c := &Client{edgeID: "dn_inconnu_du_chart", nodeName: "goproxify-edge", endpoint: srv.URL, secret: rootSecret, log: slog.Default()}
	c.ctx, c.cancel = context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(c.cancel)
	conn, err := c.dial("ws" + srv.URL[4:] + wsPath)
	if err != nil || accepted(ok, 1) != 1 {
		t.Fatalf("la clé du nom doit être acceptée : err=%v acceptées=%d", err, accepted(ok, 1))
	}
	_ = conn.Close(websocket.StatusNormalClosure, "")
	if c.lastKind.Load() == signKindRoot {
		t.Fatal("la racine n'a pas été présentée")
	}
	// La reconnexion commence par ce qui a marché, sans nouveau refus.
	if first := c.signers()[0]; !first.byName {
		t.Fatal("la clé du nom passe d'abord après un succès")
	}
}

// Quand l'identifiant et le nom donnent la même clé, elle n'est essayée qu'une fois.
func TestSignersDoNotRepeatAKeyWhenIDAndNameAreTheSame(t *testing.T) {
	t.Setenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK", "false")
	c := &Client{edgeID: "frontal", nodeName: "frontal", secret: rootSecret}
	if got := c.signers(); len(got) != 1 {
		t.Fatalf("une seule clé : %d", len(got))
	}
	c = &Client{edgeID: "dn_a", nodeName: "frontal", secret: rootSecret}
	if got := c.signers(); len(got) != 2 || got[0].byName {
		t.Fatalf("identifiant d'abord, puis nom : %+v", got)
	}
}
