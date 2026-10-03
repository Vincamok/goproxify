// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

func groupCall(t *testing.T, h *PortalHandler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rr
}

func TestPortalGroupsLifecycleAndViewResolution(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &PortalHandler{DB: db}

	rr := groupCall(t, h, http.MethodPost, "/api/v1/portal/groups?edge=edge-a", `{"name":"Prestataires","members":["Bob@Ext.fr","carl"]}`)
	if rr.Code != 200 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var g PortalGroup
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	if g.ID == "" || len(g.Members) != 2 || g.Members[0] != "bob@ext.fr" {
		t.Fatalf("groupe: %+v", g)
	}
	if rr := groupCall(t, h, http.MethodPost, "/api/v1/portal/groups?edge=edge-a", `{"name":"prestataires"}`); rr.Code != http.StatusConflict {
		t.Fatalf("doublon: %d", rr.Code)
	}

	// Config : une entrée restreinte au groupe + un utilisateur direct ; groupe inconnu ignoré.
	cfg := `{"enabled":true,"public_host":"a.example.fr","views":[{"slug":"prestataire","users":["Dan"],"groups":["` + g.ID + `","inconnu"]},{"slug":"interne"}]}`
	if rr := groupCall(t, h, http.MethodPut, "/api/v1/portal?edge=edge-a", cfg); rr.Code != 200 {
		t.Fatalf("put cfg: %d %s", rr.Code, rr.Body.String())
	}
	stored := loadPortalConfig(db, "edge-a")
	if got := stored.Views[0].Groups; len(got) != 1 || got[0] != g.ID {
		t.Fatalf("groupes conservés: %v", got)
	}
	pushed := resolveViewsForPush(db, "edge-a", stored.Views)
	if !pushed[0].Restricted || strings.Join(pushed[0].Members, ",") != "dan,bob@ext.fr,carl" || pushed[0].Groups != nil {
		t.Fatalf("entrée poussée: %+v", pushed[0])
	}
	if pushed[1].Restricted {
		t.Fatalf("une entrée sans droits reste ouverte: %+v", pushed[1])
	}
	// La config stockée n'a pas été altérée par le calcul.
	if len(stored.Views[0].Groups) != 1 {
		t.Fatal("resolveViewsForPush ne doit pas modifier la config stockée")
	}

	// Suppression : le groupe disparaît des entrées, qui restent restreintes à leurs utilisateurs directs.
	if rr := groupCall(t, h, http.MethodDelete, "/api/v1/portal/groups/"+g.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	stored = loadPortalConfig(db, "edge-a")
	if len(stored.Views[0].Groups) != 0 || len(stored.Views[0].Users) != 1 {
		t.Fatalf("après suppression: %+v", stored.Views[0])
	}
}

func TestSetUserGroups(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "g2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &PortalHandler{DB: db}
	mk := func(name string) string {
		rr := groupCall(t, h, http.MethodPost, "/api/v1/portal/groups?edge=e", `{"name":"`+name+`"}`)
		var g PortalGroup
		_ = json.Unmarshal(rr.Body.Bytes(), &g)
		return g.ID
	}
	a, b := mk("A"), mk("B")
	setUserGroups(db, "e", "Eve@x.fr", []string{a, b})
	setUserGroups(db, "e", "eve@x.fr", []string{b})
	us := []PortalUser{{Email: "eve@x.fr", HomeEdge: "e"}}
	fillUserGroups(db, us)
	if len(us[0].Groups) != 1 || us[0].Groups[0] != b {
		t.Fatalf("groupes: %v", us[0].Groups)
	}
	_ = portal.View{}
}
