// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newPair(t *testing.T) (*Store, *Store) {
	t.Helper()
	a := NewStore(filepath.Join(t.TempDir(), "a.gpx"), "cle-a")
	b := NewStore(filepath.Join(t.TempDir(), "b.gpx"), "cle-b-differente")
	return a, b
}

// sync fait converger deux magasins (échange dans les deux sens).
func syncBoth(t *testing.T, a, b *Store, withSessions bool) {
	t.Helper()
	for i := 0; i < 2; i++ {
		if _, err := b.MergeReplica(a.ExportReplica(withSessions), withSessions); err != nil {
			t.Fatal(err)
		}
		if _, err := a.MergeReplica(b.ExportReplica(withSessions), withSessions); err != nil {
			t.Fatal(err)
		}
	}
}

func admin(id, email, status string) SyncedUser {
	return SyncedUser{ID: id, Email: email, Status: status}
}

func TestReplicaConvergesBothWaysLastWriteWins(t *testing.T) {
	a, b := newPair(t)
	if err := a.CreateUser(UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "h1"}); err != nil {
		t.Fatal(err)
	}
	_ = a.SetVaultBlob("u1", []byte("coffre-v1"))
	_ = a.UpsertPersonalTarget("u1", PersonalTarget{ID: "t1", Name: "nas"})
	_ = a.SetFavorites("u1", []string{"t1"})

	syncBoth(t, a, b, false)
	u, ok := b.FindUserByID("u1")
	if !ok || u.PasswordHash != "h1" {
		t.Fatalf("le compte et son mot de passe doivent atteindre b: %+v %v", u, ok)
	}
	if string(b.VaultBlob("u1")) != "coffre-v1" || len(b.PersonalTargets("u1")) != 1 || len(b.Favorites("u1")) != 1 {
		t.Fatal("coffre, cibles perso et favoris doivent être répliqués")
	}

	// modification plus récente sur b : elle remonte vers a
	time.Sleep(2 * time.Millisecond)
	_ = b.SetVaultBlob("u1", []byte("coffre-v2"))
	syncBoth(t, a, b, false)
	if string(a.VaultBlob("u1")) != "coffre-v2" {
		t.Fatalf("la modification la plus récente doit l'emporter, a=%q", a.VaultBlob("u1"))
	}
}

func TestSyncUsersFromAdminNeverRevertsCredentials(t *testing.T) {
	a, b := newPair(t)
	list := []SyncedUser{admin("u1", "alice@example.fr", UserStatusInvited)}
	_ = a.SyncUsers(list)
	_ = b.SyncUsers(list)

	// alice choisit son mot de passe sur a
	time.Sleep(2 * time.Millisecond)
	if err := a.CompleteInvite("u1", "hash-alice"); err != nil {
		t.Fatal(err)
	}
	// l'Admin repousse la même liste à b AVANT la réplication : ne doit rien effacer
	time.Sleep(2 * time.Millisecond)
	_ = b.SyncUsers([]SyncedUser{admin("u1", "alice@example.fr", UserStatusInvited)})

	syncBoth(t, a, b, false)
	for name, s := range map[string]*Store{"a": a, "b": b} {
		u, _ := s.FindUserByID("u1")
		if u.PasswordHash != "hash-alice" || u.Status != UserStatusActive {
			t.Fatalf("%s : mot de passe et statut actif attendus, reçu %+v", name, u)
		}
	}

	// une resynchronisation Admin identique ne doit plus rien changer ni faire perdre le mot de passe
	_ = a.SyncUsers([]SyncedUser{admin("u1", "alice@example.fr", UserStatusActive)})
	_ = b.SyncUsers([]SyncedUser{admin("u1", "alice@example.fr", UserStatusActive)})
	syncBoth(t, a, b, false)
	if u, _ := a.FindUserByID("u1"); u.PasswordHash != "hash-alice" {
		t.Fatalf("mot de passe perdu après resync Admin: %+v", u)
	}
}

func TestUserCreatedByAdminAfterCompletionStillGetsCredentials(t *testing.T) {
	a, b := newPair(t)
	_ = a.SyncUsers([]SyncedUser{admin("u1", "alice@example.fr", UserStatusInvited)})
	_ = a.CompleteInvite("u1", "hash-alice")
	time.Sleep(2 * time.Millisecond)
	// b reçoit l'utilisateur de l'Admin après que le compte a été activé sur a
	_ = b.SyncUsers([]SyncedUser{admin("u1", "alice@example.fr", UserStatusInvited)})
	syncBoth(t, a, b, false)
	if u, _ := b.FindUserByID("u1"); u.PasswordHash != "hash-alice" {
		t.Fatalf("b doit récupérer le mot de passe posé sur a: %+v", u)
	}
}

func TestUserDeletedByAdminDisappearsEverywhere(t *testing.T) {
	a, b := newPair(t)
	list := []SyncedUser{admin("u1", "alice@example.fr", UserStatusActive), admin("u2", "bob@example.fr", UserStatusActive)}
	_ = a.SyncUsers(list)
	_ = b.SyncUsers(list)
	syncBoth(t, a, b, false)

	time.Sleep(2 * time.Millisecond)
	_ = a.SyncUsers([]SyncedUser{admin("u2", "bob@example.fr", UserStatusActive)}) // u1 retiré par l'Admin
	syncBoth(t, a, b, false)
	for name, s := range map[string]*Store{"a": a, "b": b} {
		if _, ok := s.FindUserByID("u1"); ok {
			t.Fatalf("%s : u1 supprimé par l'Admin ne doit pas ressusciter", name)
		}
		if _, ok := s.FindUserByID("u2"); !ok {
			t.Fatalf("%s : u2 doit rester", name)
		}
	}
}

func TestSessionsReplicateOnlyInSharedMode(t *testing.T) {
	a, b := newPair(t)
	exp := time.Now().Add(time.Hour)
	_ = a.PutAuthSession("tok-1", AuthSession{UserID: "u1", Username: "alice", VaultKey: "abcd", Expires: exp})

	syncBoth(t, a, b, false) // sticky
	if _, ok := b.GetAuthSession("tok-1"); ok {
		t.Fatal("mode sticky : une session ne doit pas quitter sa passerelle")
	}

	syncBoth(t, a, b, true) // shared
	if sess, ok := b.GetAuthSession("tok-1"); !ok || sess.VaultKey != "abcd" {
		t.Fatal("mode shared : la session doit être valable sur b")
	}

	// déconnexion sur b : la session disparaît aussi de a
	time.Sleep(2 * time.Millisecond)
	_ = b.DeleteAuthSession("tok-1")
	syncBoth(t, a, b, true)
	if _, ok := a.GetAuthSession("tok-1"); ok {
		t.Fatal("la déconnexion doit se propager")
	}
	// une session expirée n'est jamais transmise
	_ = a.PutAuthSession("tok-old", AuthSession{UserID: "u1", Expires: time.Now().Add(-time.Minute)})
	if _, ok := a.ExportReplica(true).Sessions["tok-old"]; ok {
		t.Fatal("session expirée exportée")
	}
}

func TestSameSSOAccountCreatedOnBothSidesIsMerged(t *testing.T) {
	a, b := newPair(t)
	ua, _ := a.EnsureSSOUser("bob@example.fr")
	ub, _ := b.EnsureSSOUser("bob@example.fr")
	if ua.ID == ub.ID {
		t.Fatal("précondition : identifiants différents")
	}
	_ = a.SetVaultBlob(ua.ID, []byte("coffre-bob"))
	_ = b.UpsertPersonalTarget(ub.ID, PersonalTarget{ID: "t9", Name: "vm"})

	syncBoth(t, a, b, false)
	if a.UserCount() != 1 || b.UserCount() != 1 {
		t.Fatalf("un seul compte par magasin attendu, a=%d b=%d", a.UserCount(), b.UserCount())
	}
	ua2, _ := a.FindUserByUsername("bob@example.fr")
	ub2, _ := b.FindUserByUsername("bob@example.fr")
	if ua2.ID != ub2.ID {
		t.Fatalf("les deux magasins doivent retenir le même identifiant: %s / %s", ua2.ID, ub2.ID)
	}
	if string(a.VaultBlob(ua2.ID)) != "coffre-bob" || string(b.VaultBlob(ub2.ID)) != "coffre-bob" {
		t.Fatal("le coffre doit suivre le compte fusionné")
	}
	if len(a.PersonalTargets(ua2.ID)) != 1 || len(b.PersonalTargets(ub2.ID)) != 1 {
		t.Fatal("les cibles perso doivent suivre le compte fusionné")
	}
}

func TestOnChangeFiresForLocalWritesNotForMerges(t *testing.T) {
	a, b := newPair(t)
	var fired int32
	b.SetOnChange(func() { atomic.AddInt32(&fired, 1) })

	_ = a.CreateUser(UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "h"})
	if _, err := b.MergeReplica(a.ExportReplica(false), false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&fired) != 0 {
		t.Fatal("une fusion ne doit pas déclencher de nouvel envoi (boucle d'échanges)")
	}
	_ = b.SetVaultBlob("u1", []byte("x"))
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&fired) != 1 {
		t.Fatalf("une écriture locale doit déclencher un envoi, reçu %d", atomic.LoadInt32(&fired))
	}
}

func TestReplicaSealNeedsTheGroupKey(t *testing.T) {
	a, _ := newPair(t)
	_ = a.CreateUser(UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "secret-hash"})
	sealed, err := SealReplica(a.ExportReplica(true), "cle-du-groupe")
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) == "" || containsPlain(sealed, "secret-hash") || containsPlain(sealed, "alice@example.fr") {
		t.Fatal("l'état échangé ne doit contenir aucune donnée en clair")
	}
	if _, err := OpenReplica(sealed, "autre-cle"); err == nil {
		t.Fatal("une autre clé ne doit pas déchiffrer")
	}
	if _, err := OpenReplica(sealed, ""); err == nil {
		t.Fatal("clé vide refusée")
	}
	if _, err := SealReplica(a.ExportReplica(true), ""); err == nil {
		t.Fatal("chiffrer sans clé doit échouer")
	}
	got, err := OpenReplica(sealed, "cle-du-groupe")
	if err != nil || got.Users["u1"].PasswordHash != "secret-hash" {
		t.Fatalf("aller-retour: %v %+v", err, got.Users)
	}
}

func containsPlain(data []byte, needle string) bool {
	return len(needle) > 0 && stringsContains(string(data), needle)
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
