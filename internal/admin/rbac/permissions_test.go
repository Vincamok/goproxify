// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Les capacités RGPD se détiennent par le rôle superadmin ou par une équipe qui les porte (l'équipe DPO intégrée) ;
// jamais par le seul rôle admin, qui garde seulement l'export et l'effacement.
func TestGDPRCapabilityHolders(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := rbac.EnsureBuiltInTeams(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('sa','sa@t','x','superadmin'), ('a','a@t','x','admin'),
			('dpo','dpo@t','x','user'), ('adpo','ad@t','x','admin'), ('plain','p@t','x','user')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('team-dpo','dpo'), ('team-dpo','adpo')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	reveal := map[string]bool{"sa": true, "dpo": true, "adpo": true, "a": false, "plain": false}
	exportErase := map[string]bool{"sa": true, "dpo": true, "adpo": true, "a": true, "plain": false}
	hold := map[string]bool{"sa": true, "dpo": true, "adpo": true, "a": false, "plain": false}
	for _, tc := range []struct {
		perm string
		want map[string]bool
	}{
		{rbac.PermGDPRReveal, reveal}, {rbac.PermGDPRExport, exportErase}, {rbac.PermGDPRErase, exportErase}, {rbac.PermGDPRHold, hold},
	} {
		for user, want := range tc.want {
			if got := rbac.CanExerciseGDPR(ctx, db, user, tc.perm); got != want {
				t.Errorf("%s : %s = %v, attendu %v", user, tc.perm, got, want)
			}
		}
	}
	// Le droit se lit aussi dans les scopes que le compte peut détenir (jeton API, MCP).
	for user, want := range reveal {
		if got := slices.Contains(rbac.AvailableScopesForUser(ctx, db, user), rbac.ScopeGDPRReveal); got != want {
			t.Errorf("%s : gdpr:reveal dans AvailableScopesForUser = %v, attendu %v", user, got, want)
		}
	}
	// Un compte qui détient une capacité est protégé : seul le superadmin le modifie.
	for user, want := range map[string]bool{"sa": true, "dpo": true, "adpo": true, "a": false, "plain": false} {
		if got := rbac.IsProtectedAccount(ctx, db, user); got != want {
			t.Errorf("%s : IsProtectedAccount = %v, attendu %v", user, got, want)
		}
	}
	// Le DPO reste un compte user pour le reste : pas d'écriture admin.
	if slices.Contains(rbac.AvailableScopesForUser(ctx, db, "dpo"), rbac.ScopeLogsWrite) || rbac.IsAdmin(ctx, db, "dpo") {
		t.Error("un membre de l'équipe DPO ne reçoit pas de droit d'administrateur")
	}
}

// L'équipe DPO existe d'office avec ses quatre capacités, sans accès aux ressources, et se rétablit si on la dégrade.
func TestEnsureBuiltInTeamsIsIdempotentAndRestoresCapabilities(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := rbac.EnsureBuiltInTeams(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM teams WHERE id=? AND name=?`, rbac.DPOTeamID, rbac.DPOTeamName).Scan(&n)
	if n != 1 {
		t.Fatalf("une seule équipe DPO : %d", n)
	}
	if got := rbac.TeamPermissions(ctx, db, rbac.DPOTeamID); !slices.Equal(got, []string{"gdpr:erase", "gdpr:export", "gdpr:hold", "gdpr:reveal"}) {
		t.Fatalf("capacités de l'équipe DPO : %v", got)
	}
	_, _ = db.Exec(`DELETE FROM team_permissions WHERE team_id=? AND permission='gdpr:hold'`, rbac.DPOTeamID)
	if err := rbac.EnsureBuiltInTeams(ctx, db); err != nil {
		t.Fatal(err)
	}
	if len(rbac.TeamPermissions(ctx, db, rbac.DPOTeamID)) != 4 {
		t.Fatal("une capacité retirée de l'équipe DPO doit être rétablie au démarrage")
	}
	var scopes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM team_accesses WHERE team_id=?`, rbac.DPOTeamID).Scan(&scopes)
	if scopes != 0 {
		t.Fatal("l'équipe DPO ne porte aucun accès sur les ressources")
	}
	if !rbac.IsBuiltInTeam(rbac.DPOTeamID) || rbac.IsBuiltInTeam("autre") {
		t.Fatal("IsBuiltInTeam")
	}
}

func TestNormalizePermissions(t *testing.T) {
	if got, ok := rbac.NormalizePermissions([]string{"gdpr:reveal", "gdpr:reveal"}); !ok || !slices.Equal(got, []string{"gdpr:reveal"}) {
		t.Fatalf("doublon : %v %v", got, ok)
	}
	if got, ok := rbac.NormalizePermissions([]string{"gdpr:hold", "gdpr:reveal"}); !ok || !slices.Equal(got, []string{"gdpr:reveal", "gdpr:hold"}) {
		t.Fatalf("ordre de KnownPermissions : %v %v", got, ok)
	}
	if _, ok := rbac.NormalizePermissions([]string{"logs:write"}); ok {
		t.Fatal("permission inconnue acceptée")
	}
	if got, ok := rbac.NormalizePermissions(nil); !ok || got != nil {
		t.Fatalf("vide : %v %v", got, ok)
	}
}
