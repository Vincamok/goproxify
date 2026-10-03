// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestPortalDestGroupsLifecycleAndViewResolution(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "dg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &PortalHandler{DB: db}

	mkDest := func(name string) string {
		rr := groupCall(t, h, http.MethodPost, "/api/v1/portal/destinations", `{"edge_name":"edge-a","kind":"ssh","name":"`+name+`","host":"10.0.0.1"}`)
		var d PortalDestination
		_ = json.Unmarshal(rr.Body.Bytes(), &d)
		if d.ID == "" {
			t.Fatalf("destination %s: %d %s", name, rr.Code, rr.Body.String())
		}
		return d.ID
	}
	d1, d2, d3 := mkDest("web-1"), mkDest("web-2"), mkDest("db-1")

	rr := groupCall(t, h, http.MethodPost, destGroupsPath+"?edge=edge-a", `{"name":"Web","targets":["`+d1+`","`+d2+`","inconnue"]}`)
	if rr.Code != 200 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var g PortalDestGroup
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	if g.ID == "" || len(g.Targets) != 2 {
		t.Fatalf("groupe (destination inconnue ignorée) : %+v", g)
	}
	if rr := groupCall(t, h, http.MethodPost, destGroupsPath+"?edge=edge-a", `{"name":"web"}`); rr.Code != http.StatusConflict {
		t.Fatalf("doublon: %d", rr.Code)
	}

	cfg := `{"enabled":true,"public_host":"a.example.fr","views":[{"slug":"presta","target_ids":["` + d3 + `"],"dest_groups":["` + g.ID + `","inconnu"]}]}`
	if rr := groupCall(t, h, http.MethodPut, "/api/v1/portal?edge=edge-a", cfg); rr.Code != 200 {
		t.Fatalf("put cfg: %d %s", rr.Code, rr.Body.String())
	}
	stored := loadPortalConfig(db, "edge-a")
	if got := stored.Views[0].DestGroups; len(got) != 1 || got[0] != g.ID {
		t.Fatalf("groupes conservés: %v", got)
	}
	pushed := resolveViewsForPush(db, "edge-a", stored.Views)
	if pushed[0].DestGroups != nil || strings.Join(pushed[0].TargetIDs, ",") != d3+","+d1+","+d2 {
		t.Fatalf("entrée poussée: %+v", pushed[0])
	}
	if len(stored.Views[0].DestGroups) != 1 {
		t.Fatal("resolveViewsForPush ne doit pas modifier la config stockée")
	}

	// Supprimer une destination la retire du groupe.
	if rr := groupCall(t, h, http.MethodDelete, "/api/v1/portal/destinations/"+d1, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete dest: %d", rr.Code)
	}
	if got := listPortalDestGroups(db, "edge-a")[0].Targets; len(got) != 1 || got[0] != d2 {
		t.Fatalf("cibles après suppression de destination: %v", got)
	}

	// Supprimer le groupe le retire des entrées.
	if rr := groupCall(t, h, http.MethodDelete, destGroupsPath+"/"+g.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	stored = loadPortalConfig(db, "edge-a")
	if len(stored.Views[0].DestGroups) != 0 || len(stored.Views[0].TargetIDs) != 1 {
		t.Fatalf("après suppression: %+v", stored.Views[0])
	}
}
