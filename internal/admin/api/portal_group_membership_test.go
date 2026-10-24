// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
)

func setMember(t *testing.T, s *archstore.Store, id, name, group string) {
	t.Helper()
	cfg := `{"cluster": false, "portal": true}`
	if group != "" {
		cfg = `{"cluster": true, "cluster_group": "` + group + `", "portal": true}`
	}
	if err := s.Upsert(archstore.NodeEntry{ID: id, Role: "edge", Name: name, Config: json.RawMessage(cfg)}); err != nil {
		t.Fatal(err)
	}
}

func membership(t *testing.T) (*api.GroupMembership, *recordingPusher, *archstore.Store, func() string) {
	t.Helper()
	db, store, groups := portalFixture(t)
	pusher := &recordingPusher{}
	gm := &api.GroupMembership{DB: db, Groups: groups, Pusher: pusher, Log: slog.Default()}
	key := func() string { return api.BuildPortalPayload(db, groups, "frontal").HAKey }
	return gm, pusher, store, key
}

// Le premier passage retient la composition sans rien pousser ni renouveler : pas de rotation rétroactive.
func TestMembershipFirstPassOnlyRemembers(t *testing.T) {
	gm, pusher, _, key := membership(t)
	before := key()
	gm.Reconcile(context.Background())
	if len(pusher.sent) != 0 || key() != before {
		t.Fatalf("premier passage : envois %v, clé changée %v", pusher.sent, key() != before)
	}
	gm.Reconcile(context.Background())
	if len(pusher.sent) != 0 {
		t.Fatal("composition inchangée : aucun envoi")
	}
}

// Un membre sorti : la clé du groupe change, les membres restants la reçoivent avec la liste à jour, et le membre sorti
// reçoit la configuration de son propre groupe, sans champs HA.
func TestMembershipRemovedMemberRotatesTheKey(t *testing.T) {
	gm, pusher, store, key := membership(t)
	ctx := context.Background()
	old := key()
	if old == "" {
		t.Fatal("le groupe a une clé")
	}
	gm.Reconcile(ctx)

	setMember(t, store, "dn_b", "backup", "") // backup quitte ha-1
	gm.Reconcile(ctx)

	newKey := key()
	if newKey == "" || newKey == old {
		t.Fatalf("la clé du groupe doit être renouvelée : %q → %q", old, newKey)
	}
	front := pusher.sent["frontal"]
	if front.HAKey != newKey || len(front.HAMembers) != 1 || front.HAMembers[0] != "frontal" {
		t.Fatalf("le membre restant reçoit la nouvelle clé et la liste à jour : %+v", front)
	}
	out := pusher.sent["backup"]
	if out.HAGroup != "" || out.HAKey != "" || len(out.HAMembers) != 0 {
		t.Fatalf("le membre sorti reçoit sa propre configuration, sans champs HA : %+v", out)
	}

	// Plus rien à faire au passage suivant.
	before := len(pusher.sent)
	pusher.sent = map[string]api.PortalConfig{}
	gm.Reconcile(ctx)
	if len(pusher.sent) != 0 || before == 0 || key() != newKey {
		t.Fatalf("composition retenue : %v", pusher.sent)
	}
}

// Un membre ajouté : tous reçoivent la liste à jour, la clé ne change pas.
func TestMembershipAddedMemberKeepsTheKey(t *testing.T) {
	gm, pusher, store, key := membership(t)
	ctx := context.Background()
	old := key()
	gm.Reconcile(ctx)

	setMember(t, store, "dn_s", "seul", "ha-1")
	gm.Reconcile(ctx)

	if key() != old {
		t.Fatal("un ajout ne change pas la clé")
	}
	for _, name := range []string{"frontal", "backup", "seul"} {
		cfg, ok := pusher.sent[name]
		if !ok || len(cfg.HAMembers) != 3 || cfg.HAKey != old {
			t.Fatalf("%s doit recevoir la liste des 3 membres et la même clé : %+v (envoyé %v)", name, cfg, ok)
		}
	}
}

// Un membre qui change de groupe quitte l'ancien (clé renouvelée) et entre dans l'autre (liste poussée).
func TestMembershipMovedMemberLeavesOneAndJoinsAnother(t *testing.T) {
	gm, pusher, store, key := membership(t)
	ctx := context.Background()
	old := key()
	gm.Reconcile(ctx)

	setMember(t, store, "dn_b", "backup", "ha-2")
	gm.Reconcile(ctx)

	if key() == old {
		t.Fatal("ha-1 perd un membre : sa clé change")
	}
	if got := pusher.sent["backup"]; got.HAGroup != "ha-2" || got.HAKey == "" || got.HAKey == old {
		t.Fatalf("backup reçoit la configuration de son nouveau groupe, pas la clé de l'ancien : %+v", got)
	}
}

// Un groupe dont plus aucun membre n'est déclaré n'est tenu pour dissous qu'après deux passages ; un passage où aucun
// groupe n'est lu ne conclut rien.
func TestMembershipDissolvedGroupNeedsTwoPasses(t *testing.T) {
	gm, pusher, store, _ := membership(t)
	ctx := context.Background()
	setMember(t, store, "dn_x", "extra", "ha-3")
	setMember(t, store, "dn_y", "extra2", "ha-3")
	gm.Reconcile(ctx)

	setMember(t, store, "dn_x", "extra", "")
	setMember(t, store, "dn_y", "extra2", "")
	gm.Reconcile(ctx)
	if len(pusher.sent) != 0 {
		t.Fatalf("un seul passage ne conclut pas : %v", pusher.sent)
	}
	gm.Reconcile(ctx)
	for _, name := range []string{"extra", "extra2"} {
		cfg, ok := pusher.sent[name]
		if !ok || cfg.HAGroup != "" || cfg.HAKey != "" {
			t.Fatalf("%s reçoit sa propre configuration après deux passages : %+v (envoyé %v)", name, cfg, ok)
		}
	}
}

type fakeRotator struct{ got []string }

func (f *fakeRotator) RotateEdgeTokens(_ context.Context, refs []string) { f.got = append(f.got, refs...) }

// Quand un membre sort, les membres restants voient leur jeton renouvelé : le membre sorti connaît ceux de ses pairs. Un
// membre qui entre ne change aucun jeton.
func TestMembershipRemovedMemberRotatesTheRemainingTokens(t *testing.T) {
	gm, _, store, _ := membership(t)
	rot := &fakeRotator{}
	gm.Tokens = rot
	ctx := context.Background()
	gm.Reconcile(ctx)

	setMember(t, store, "dn_x", "nouveau", "ha-1") // un membre entre
	gm.Reconcile(ctx)
	if len(rot.got) != 0 {
		t.Fatalf("une arrivée ne renouvelle aucun jeton : %v", rot.got)
	}

	setMember(t, store, "dn_b", "backup", "") // backup sort
	gm.Reconcile(ctx)
	got := map[string]bool{}
	for _, n := range rot.got {
		got[n] = true
	}
	if len(got) != 2 || !got["frontal"] || !got["nouveau"] || got["backup"] {
		t.Fatalf("les jetons des membres restants sont renouvelés, pas celui du sorti : %v", rot.got)
	}
}
