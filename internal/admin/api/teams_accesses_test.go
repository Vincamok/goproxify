// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Un accès d'équipe se crée, se relit, se remplace et se supprime ; ce qu'une équipe ne peut pas tenir est refusé.
func TestTeamAccessesLifecycle(t *testing.T) {
	db, do := permsFixture(t)
	teams := &TeamsHandler{DB: db, Log: slog.Default()}

	var created rbac.TeamAccess
	rec := do(teams, http.MethodPost, "/api/v1/teams/ops/accesses", "a", map[string]any{
		"name":        "Exploitation prod",
		"perimeter":   map[string]any{"labels": map[string]string{"env": "prod"}, "domain": "*.corp.io"},
		"levels":      map[string]string{"proxies": "operate", "logs": "read", "alerts": "ack"},
		"permissions": []string{"certs:deploy"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body)
	}
	json.Unmarshal(rec.Body.Bytes(), &created) //nolint:errcheck
	if created.ID == "" || created.TeamID != "ops" || created.Perimeter.Labels["env"] != "prod" {
		t.Fatalf("accès créé : %+v", created)
	}

	var list []rbac.TeamAccess
	json.Unmarshal(do(teams, http.MethodGet, "/api/v1/teams/ops/accesses", "a", nil).Body.Bytes(), &list) //nolint:errcheck
	if len(list) != 1 || list[0].Levels["alerts"] != "ack" || !slices.Equal(list[0].Permissions, []string{"certs:deploy"}) {
		t.Fatalf("liste : %+v", list)
	}

	rec = do(teams, http.MethodPut, "/api/v1/teams/ops/accesses/"+created.ID, "a", map[string]any{
		"name": "Exploitation prod", "levels": map[string]string{"proxies": "read"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("remplacement : %d %s", rec.Code, rec.Body)
	}
	list = nil // json.Unmarshal fusionnerait les cartes de l'élément précédent
	json.Unmarshal(do(teams, http.MethodGet, "/api/v1/teams/ops/accesses", "a", nil).Body.Bytes(), &list) //nolint:errcheck
	if len(list) != 1 || list[0].Levels["proxies"] != "read" || len(list[0].Permissions) != 0 || !list[0].Perimeter.IsEmpty() {
		t.Fatalf("un PUT remplace l'accès entier : %+v", list)
	}

	var teamList []teamRow
	json.Unmarshal(do(teams, http.MethodGet, "/api/v1/teams", "a", nil).Body.Bytes(), &teamList) //nolint:errcheck
	for _, tm := range teamList {
		if tm.ID == "ops" && tm.AccessCount != 1 {
			t.Errorf("access_count de l'équipe : %d", tm.AccessCount)
		}
	}

	if rec := do(teams, http.MethodDelete, "/api/v1/teams/ops/accesses/"+created.ID, "a", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("suppression : %d", rec.Code)
	}
	if rec := do(teams, http.MethodDelete, "/api/v1/teams/ops/accesses/"+created.ID, "a", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("deuxième suppression : %d", rec.Code)
	}
	if rec := do(teams, http.MethodPut, "/api/v1/teams/ops/accesses/absent", "a", map[string]any{"levels": map[string]string{}}); rec.Code != http.StatusNotFound {
		t.Fatalf("remplacement d'un accès absent : %d", rec.Code)
	}
}

func TestTeamAccessesRefuseWhatATeamCannotHold(t *testing.T) {
	db, do := permsFixture(t)
	teams := &TeamsHandler{DB: db, Log: slog.Default()}
	for name, body := range map[string]map[string]any{
		"service inconnu":          {"levels": map[string]string{"inconnu": "read"}},
		"niveau inconnu":           {"levels": map[string]string{"proxies": "dieu"}},
		"écriture d'objet partagé": {"levels": map[string]string{"snippets": "write"}},
		"capacité RGPD":            {"permissions": []string{"gdpr:reveal"}},
		"accorder des droits":      {"permissions": []string{"teams:write"}},
		"expression invalide":      {"perimeter": map[string]any{"proxy": "re:("}},
		"étiquette invalide":       {"perimeter": map[string]any{"labels": map[string]string{"Env": "prod"}}},
	} {
		if rec := do(teams, http.MethodPost, "/api/v1/teams/ops/accesses", "a", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d, attendu 400 (%s)", name, rec.Code, rec.Body)
		}
	}
	if n := len(mustAccesses(t, db, "ops")); n != 0 {
		t.Fatalf("un refus ne doit rien enregistrer : %d accès", n)
	}
}

func mustAccesses(t *testing.T, db *sql.DB, team string) []rbac.TeamAccess {
	t.Helper()
	list, err := rbac.TeamAccesses(context.Background(), db, team)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// Le catalogue de droits et l'aperçu d'un périmètre sont servis aux administrateurs.
func TestRightsCatalogAndPreview(t *testing.T) {
	h := &RightsHandler{
		Log: slog.Default(),
		Routes: func(context.Context) ([]router.Route, error) {
			return []router.Route{
				{ID: "1", Name: "alpha-1", Host: "a.corp.io", Labels: map[string]string{"env": "prod"}},
				{ID: "2", Name: "alpha-2", Host: "b.corp.io", Labels: map[string]string{"env": "test"}},
				{ID: "3", Host: "c.other.io"},
			}, nil
		},
	}
	_, do := permsFixture(t)

	var cat struct {
		Services []rbac.Service `json:"services"`
		Profiles []rbac.Profile `json:"profiles"`
		Criteria []string       `json:"criteria"`
	}
	rec := do(h, http.MethodGet, "/api/v1/rights/catalog", "a", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalogue : %d", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &cat) //nolint:errcheck
	if len(cat.Services) != len(rbac.Services) || len(cat.Profiles) != len(rbac.Profiles) || len(cat.Criteria) != 5 {
		t.Fatalf("catalogue incomplet : %d services, %d profils, %d critères", len(cat.Services), len(cat.Profiles), len(cat.Criteria))
	}

	preview := func(perimeter map[string]any) (int, int, int) {
		rec := do(h, http.MethodPost, "/api/v1/rights/preview", "a", map[string]any{"perimeter": perimeter})
		var out struct {
			Count, Total int
			Proxies      []previewProxy
		}
		json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
		return rec.Code, out.Count, len(out.Proxies)
	}
	if code, count, listed := preview(map[string]any{"labels": map[string]string{"env": "prod"}}); code != 200 || count != 1 || listed != 1 {
		t.Errorf("étiquette env=prod : %d %d %d", code, count, listed)
	}
	if code, count, _ := preview(map[string]any{"proxy": "re:^alpha-\\d+$"}); code != 200 || count != 2 {
		t.Errorf("expression régulière : %d %d", code, count)
	}
	if code, count, _ := preview(map[string]any{}); code != 200 || count != 3 {
		t.Errorf("périmètre vide = tout : %d %d", code, count)
	}
	if code, _, _ := preview(map[string]any{"proxy": "re:("}); code != http.StatusBadRequest {
		t.Errorf("périmètre invalide : %d", code)
	}
}
