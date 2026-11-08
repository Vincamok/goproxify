// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/destsync"
)

func destTestEnv(t *testing.T) (*sql.DB, *PortalHandler, *pushRecorder) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "ds.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	p := &pushRecorder{}
	return db, &PortalHandler{DB: db, Pusher: p}, p
}

func createProxmoxSource(t *testing.T, h *PortalHandler, extra string) DestSource {
	t.Helper()
	body := `{"edge_name":"edge-a","type":"proxmox","name":"pve","config":{"url":"https://pve:8006","token_id":"a@pve!t","token_secret":"s3cret"}` + extra + `}`
	rr := groupCall(t, h, http.MethodPost, destSourcesPath, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create source: %d %s", rr.Code, rr.Body.String())
	}
	var d DestSource
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func inventory(src DestSource, machines ...destsync.Machine) destsync.Inventory {
	return destsync.Inventory{SourceID: src.ID, Type: src.Type, OK: true, At: time.Now(), Machines: machines}
}

func apply(t *testing.T, db *sql.DB, p PortalPusher, node string, inv destsync.Inventory) {
	t.Helper()
	if err := ApplyDestInventory(context.Background(), db, slogDiscard(), nil, p, node, inv); err != nil {
		t.Fatal(err)
	}
}

func candidates(t *testing.T, h *PortalHandler, query string) map[string]DestCandidate {
	t.Helper()
	rr := groupCall(t, h, http.MethodGet, destCandidatesPath+query, "")
	var out struct {
		Candidates []DestCandidate `json:"candidates"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	m := map[string]DestCandidate{}
	for _, c := range out.Candidates {
		m[c.ExternalID] = c
	}
	return m
}

func destinationRow(t *testing.T, db *sql.DB, id string) (name, host string, port, enabled int, tags string) {
	t.Helper()
	if err := db.QueryRow(`SELECT name, host, port, enabled, tags_json FROM portal_destinations WHERE id=?`, id).Scan(&name, &host, &port, &enabled, &tags); err != nil {
		t.Fatalf("destination %s : %v", id, err)
	}
	return
}

func TestDestSourceSecretsAreSealedMaskedAndKept(t *testing.T) {
	auth.ConfigureNodeTokenKey("cle-de-test")
	t.Cleanup(func() { auth.ConfigureNodeTokenKey("") })
	db, h, _ := destTestEnv(t)
	src := createProxmoxSource(t, h, "")

	if src.Config["token_secret"] == "s3cret" || src.Config["token_secret"] != "••••••••" {
		t.Fatalf("le secret doit être masqué dans la réponse : %v", src.Config["token_secret"])
	}
	var enc string
	_ = db.QueryRow(`SELECT config_enc FROM portal_dest_sources WHERE id=?`, src.ID).Scan(&enc)
	if enc == "" || strings.Contains(enc, "s3cret") || !strings.HasPrefix(enc, "gpxnt1:") {
		t.Fatal("le secret ne doit pas être stocké en clair")
	}
	if rr := groupCall(t, h, http.MethodGet, destSourcesPath+"?edge=edge-a", ""); strings.Contains(rr.Body.String(), "s3cret") {
		t.Fatal("la liste ne doit jamais renvoyer le secret")
	}

	// Modifier sans ressaisir le secret (masque renvoyé par le formulaire) le conserve.
	rr := groupCall(t, h, http.MethodPut, destSourcesPath+"/"+src.ID,
		`{"name":"pve2","config":{"url":"https://pve2:8006","token_id":"a@pve!t","token_secret":"••••••••"}}`)
	if rr.Code != 200 {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	stored, _ := loadDestSource(db, src.ID)
	if stored.Config["token_secret"] != "s3cret" || stored.Config["url"] != "https://pve2:8006" || stored.Name != "pve2" {
		t.Fatalf("secret perdu ou config non mise à jour : %+v", stored.Config)
	}

	for name, tc := range map[string]struct{ method, path, body string }{
		"type inconnu":      {"POST", destSourcesPath, `{"edge_name":"edge-a","type":"nope","name":"x","config":{}}`},
		"champ requis":      {"POST", destSourcesPath, `{"edge_name":"edge-a","type":"proxmox","name":"x","config":{"url":"https://pve:8006"}}`},
		"clé inconnue":      {"POST", destSourcesPath, `{"edge_name":"edge-a","type":"proxmox","name":"x","config":{"url":"https://pve:8006","token_id":"a","token_secret":"b","zzz":1}}`},
		"url invalide":      {"POST", destSourcesPath, `{"edge_name":"edge-a","type":"proxmox","name":"x","config":{"url":"ftp://x","token_id":"a","token_secret":"b"}}`},
		"changer de type":   {"PUT", destSourcesPath + "/" + src.ID, `{"type":"hetzner"}`},
		"changer de portée": {"PUT", destSourcesPath + "/" + src.ID, `{"edge_name":"edge-b"}`},
	} {
		if rr := groupCall(t, h, tc.method, tc.path, tc.body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s : %d %s", name, rr.Code, rr.Body.String())
		}
	}
	if rr := groupCall(t, h, http.MethodPost, destSourcesPath, `{"edge_name":"edge-a","type":"proxmox","name":"PVE2","config":{"url":"https://pve:8006","token_id":"a","token_secret":"b"}}`); rr.Code != http.StatusConflict {
		t.Errorf("doublon de nom : %d", rr.Code)
	}
}

func TestDestSourcesAreSentToTheGatewayWithTheirSecrets(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, `,"interval_s":120`)
	if len(pusher.pushed) == 0 {
		t.Fatal("créer une source doit pousser la config du portail")
	}
	cfg := BuildPortalPayload(db, nil, "edge-a")
	if len(cfg.DestSources) != 1 || cfg.DestSources[0].ID != src.ID || cfg.DestSources[0].Config["token_secret"] != "s3cret" ||
		cfg.DestSources[0].IntervalS != 120 || !cfg.DestSources[0].Enabled {
		t.Fatalf("la passerelle reçoit la source avec son secret : %+v", cfg.DestSources)
	}
	// La config renvoyée à l'UI (GET /portal) ne porte jamais les sources.
	rr := groupCall(t, h, http.MethodGet, "/api/v1/portal?edge=edge-a", "")
	if strings.Contains(rr.Body.String(), "s3cret") || strings.Contains(rr.Body.String(), src.ID) {
		t.Fatalf("GET /portal ne doit pas exposer les sources : %s", rr.Body.String())
	}
	// Sans source, la liste poussée est vide mais non nulle : elle retire ce que la passerelle exécutait.
	groupCall(t, h, http.MethodDelete, destSourcesPath+"/"+src.ID, "")
	raw, _ := json.Marshal(BuildPortalPayload(db, nil, "edge-a"))
	if !strings.Contains(string(raw), `"dest_sources":[]`) {
		t.Fatalf("liste vide attendue : %s", raw)
	}
}

func TestInventoryFeedsCandidatesWithoutPublishing(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, `,"extra_tags":["Proxmox"]`)
	pusher.pushed = nil

	apply(t, db, pusher, "edge-a", inventory(src,
		destsync.Machine{ExternalID: "qemu/100", Name: "web", Host: "10.0.0.5", Port: 22, Tags: []string{"prod"}, Running: true},
		destsync.Machine{ExternalID: "lxc/200", Name: "db", Port: 22}))

	got := candidates(t, h, "?edge=edge-a")
	if len(got) != 2 || got["qemu/100"].State != CandNew || got["lxc/200"].State != CandNew {
		t.Fatalf("candidates : %+v", got)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_destinations`).Scan(&n)
	if n != 0 || len(pusher.pushed) != 0 {
		t.Fatalf("rien ne doit être publié ni poussé sans validation (destinations=%d, poussées=%d)", n, len(pusher.pushed))
	}
	if got["qemu/100"].SourceName != "pve" || got["qemu/100"].SourceType != "proxmox" {
		t.Fatalf("source de la candidate : %+v", got["qemu/100"])
	}
	s, _ := loadDestSource(db, src.ID)
	if s.Status != "ok" || s.MachineCount != 2 || s.LastSyncAt == "" {
		t.Fatalf("état de la source : %+v", s)
	}
}

func TestPublishCreatesASSHDestinationAndFollowsTheProvider(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, `,"extra_tags":["Proxmox"]`)
	apply(t, db, pusher, "edge-a", inventory(src,
		destsync.Machine{ExternalID: "qemu/100", Name: "web", Host: "10.0.0.5", Port: 22, Tags: []string{"prod"}, Running: true},
		destsync.Machine{ExternalID: "lxc/200", Name: "db", Port: 22}))
	cands := candidates(t, h, "")
	web, db200 := cands["qemu/100"], cands["lxc/200"]
	pusher.pushed = nil

	rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+web.ID+"/publish", `{"tags":["Ops"]}`)
	if rr.Code != 200 {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	var res struct {
		DestinationID string `json:"destination_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	name, host, port, enabled, tags := destinationRow(t, db, res.DestinationID)
	if name != "web" || host != "10.0.0.5" || port != 22 || enabled != 1 || tags != `["prod","proxmox","ops"]` {
		t.Fatalf("destination : %s %s %d %d %s", name, host, port, enabled, tags)
	}
	var kind, edge string
	_ = db.QueryRow(`SELECT kind, edge_name FROM portal_destinations WHERE id=?`, res.DestinationID).Scan(&kind, &edge)
	if kind != "ssh" || edge != "edge-a" || len(pusher.pushed) != 1 {
		t.Fatalf("kind=%s edge=%s poussées=%d", kind, edge, len(pusher.pushed))
	}
	if again := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+web.ID+"/publish", ""); again.Code != http.StatusConflict {
		t.Fatalf("republier: %d", again.Code)
	}

	// Une machine sans adresse est refusée, puis acceptée si l'opérateur la saisit.
	if rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+db200.ID+"/publish", ""); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "adresse") {
		t.Fatalf("sans adresse: %d %s", rr.Code, rr.Body.String())
	}
	rr = groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+db200.ID+"/publish", `{"host":"10.0.0.99","name":"base"}`)
	if rr.Code != 200 {
		t.Fatalf("avec adresse saisie: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if n, hst, _, _, _ := destinationRow(t, db, res.DestinationID); n != "base" || hst != "10.0.0.99" {
		t.Fatalf("surcharges: %s %s", n, hst)
	}

	// Le fournisseur renomme et déplace la machine : la destination suit.
	apply(t, db, pusher, "edge-a", inventory(src,
		destsync.Machine{ExternalID: "qemu/100", Name: "web-new", Host: "10.0.0.6", Port: 2200, Tags: []string{"prod"}, Running: true},
		destsync.Machine{ExternalID: "lxc/200", Name: "db-renamed", Host: "10.0.0.7", Port: 22}))
	webID := candidates(t, h, "")["qemu/100"].DestID
	if n, hst, p, _, _ := destinationRow(t, db, webID); n != "web-new" || hst != "10.0.0.6" || p != 2200 {
		t.Fatalf("la destination doit suivre le fournisseur : %s %s %d", n, hst, p)
	}
	// ...sauf ce que l'opérateur a corrigé à la main (nom et adresse saisis à la publication de lxc/200).
	dbID := candidates(t, h, "")["lxc/200"].DestID
	if n, hst, _, _, _ := destinationRow(t, db, dbID); n != "base" || hst != "10.0.0.99" {
		t.Fatalf("une valeur saisie à la main ne doit pas être écrasée : %s %s", n, hst)
	}
}

func TestDisappearedMachinesAreDisabledNeverDeleted(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, "")
	m := func(id, host string) destsync.Machine {
		return destsync.Machine{ExternalID: id, Name: id, Host: host, Port: 22, Running: true}
	}
	apply(t, db, pusher, "edge-a", inventory(src, m("a", "10.0.0.1"), m("b", "10.0.0.2"), m("c", "10.0.0.3")))
	cands := candidates(t, h, "")
	groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+cands["a"].ID+"/publish", "")
	groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+cands["b"].ID+"/ignore", "")
	pusher.pushed = nil

	// Une panne du fournisseur ne touche à rien.
	apply(t, db, pusher, "edge-a", destsync.Inventory{SourceID: src.ID, OK: false, Error: "api en panne"})
	if got := candidates(t, h, ""); len(got) != 3 || got["a"].State != CandPublished {
		t.Fatalf("une erreur ne modifie aucune candidate : %+v", got)
	}
	if s, _ := loadDestSource(db, src.ID); s.Status != "error" || s.StatusMsg != "api en panne" || s.MachineCount != 3 {
		t.Fatalf("état d'erreur : %+v", s)
	}
	if len(pusher.pushed) != 0 {
		t.Fatal("une erreur ne pousse rien")
	}

	// Un inventaire réussi sans a, b ni c.
	apply(t, db, pusher, "edge-a", inventory(src))
	got := candidates(t, h, "")
	if len(got) != 1 || got["a"].State != CandMissing {
		t.Fatalf("publiée absente → missing ; nouvelle et ignorée absentes → retirées : %+v", got)
	}
	if _, _, _, enabled, _ := destinationRow(t, db, got["a"].DestID); enabled != 0 {
		t.Fatal("la destination d'une machine disparue doit être désactivée")
	}
	if len(pusher.pushed) != 1 {
		t.Fatalf("le catalogue modifié doit être poussé (%d)", len(pusher.pushed))
	}

	// Elle revient : la destination est réactivée.
	apply(t, db, pusher, "edge-a", inventory(src, m("a", "10.0.0.1")))
	got = candidates(t, h, "")
	if got["a"].State != CandPublished {
		t.Fatalf("retour de la machine : %+v", got["a"])
	}
	if _, _, _, enabled, _ := destinationRow(t, db, got["a"].DestID); enabled != 1 {
		t.Fatal("la destination doit être réactivée")
	}
}

func TestDeletingADestinationPutsTheMachineBackInTheQueue(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, "")
	apply(t, db, pusher, "edge-a", inventory(src, destsync.Machine{ExternalID: "a", Name: "a", Host: "10.0.0.1", Port: 22}))
	c := candidates(t, h, "")["a"]
	groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+c.ID+"/publish", "")
	published := candidates(t, h, "")["a"]

	groupCall(t, h, http.MethodDelete, "/api/v1/portal/destinations/"+published.DestID, "")
	if got := candidates(t, h, "")["a"]; got.State != CandNew || got.DestID != "" {
		t.Fatalf("après suppression de la destination : %+v", got)
	}
	// Et une candidate dont la destination a disparu sans passer par l'API est aussi remise dans la file au passage suivant.
	groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+c.ID+"/publish", "")
	id := candidates(t, h, "")["a"].DestID
	_, _ = db.Exec(`DELETE FROM portal_destinations WHERE id=?`, id)
	apply(t, db, pusher, "edge-a", inventory(src, destsync.Machine{ExternalID: "a", Name: "a", Host: "10.0.0.1", Port: 22}))
	if got := candidates(t, h, "")["a"]; got.State != CandNew {
		t.Fatalf("destination disparue : %+v", got)
	}
}

func TestAutoPublishAndIgnoreRestoreAndBulkPublish(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	auto := createProxmoxSource(t, h, `,"auto_publish":true`)
	apply(t, db, pusher, "edge-a", inventory(auto,
		destsync.Machine{ExternalID: "a", Name: "a", Host: "10.0.0.1", Port: 22},
		destsync.Machine{ExternalID: "noaddr", Name: "x", Port: 22}))
	got := candidates(t, h, "")
	if got["a"].State != CandPublished || got["a"].DestID == "" {
		t.Fatalf("auto_publish : %+v", got["a"])
	}
	if got["noaddr"].State != CandNew {
		t.Fatalf("sans adresse, rien ne se publie seul : %+v", got["noaddr"])
	}

	manual := groupCall(t, h, http.MethodPost, destSourcesPath, `{"edge_name":"edge-a","type":"proxmox","name":"manuel","config":{"url":"https://pve:8006","token_id":"a","token_secret":"b"}}`)
	var ms DestSource
	_ = json.Unmarshal(manual.Body.Bytes(), &ms)
	apply(t, db, pusher, "edge-a", inventory(ms,
		destsync.Machine{ExternalID: "m1", Name: "m1", Host: "10.1.0.1", Port: 22},
		destsync.Machine{ExternalID: "m2", Name: "m2", Host: "10.1.0.2", Port: 22},
		destsync.Machine{ExternalID: "m3", Name: "m3", Port: 22}))
	cs := candidates(t, h, "?source="+ms.ID)
	if rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+cs["m2"].ID+"/ignore", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("ignore: %d", rr.Code)
	}
	if rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+cs["m2"].ID+"/ignore", ""); rr.Code != http.StatusConflict {
		t.Fatalf("ignorer deux fois: %d", rr.Code)
	}
	if rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+cs["m2"].ID+"/restore", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("restore: %d", rr.Code)
	}
	rr := groupCall(t, h, http.MethodPost, destCandidatesPath+"/publish",
		`{"ids":["`+cs["m1"].ID+`","`+cs["m2"].ID+`","`+cs["m3"].ID+`","inconnu"],"tags":["x"]}`)
	var out struct {
		Published int `json:"published"`
		Skipped   []struct {
			ID, Reason string
		} `json:"skipped"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Published != 2 || len(out.Skipped) != 2 {
		t.Fatalf("publication en lot : %s", rr.Body.String())
	}
	if rr := groupCall(t, h, http.MethodDelete, destCandidatesPath+"/"+cs["m1"].ID, ""); rr.Code != http.StatusConflict {
		t.Fatalf("une machine publiée ne se retire pas de la file : %d", rr.Code)
	}
	if rr := groupCall(t, h, http.MethodDelete, destCandidatesPath+"/"+cs["m3"].ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("retirer une candidate non publiée : %d", rr.Code)
	}
}

func TestInventoryFromAnotherScopeOrUnknownSourceIsIgnored(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, "")
	apply(t, db, pusher, "edge-b", inventory(src, destsync.Machine{ExternalID: "a", Name: "a", Host: "10.0.0.1"})) // autre passerelle
	apply(t, db, pusher, "edge-a", destsync.Inventory{SourceID: "inconnue", OK: true, Machines: []destsync.Machine{{ExternalID: "a"}}})
	if got := candidates(t, h, ""); len(got) != 0 {
		t.Fatalf("aucun inventaire étranger ne doit être retenu : %+v", got)
	}
}

func TestDeletingASourceKeepsPublishedDestinations(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	src := createProxmoxSource(t, h, "")
	apply(t, db, pusher, "edge-a", inventory(src, destsync.Machine{ExternalID: "a", Name: "a", Host: "10.0.0.1", Port: 22}))
	groupCall(t, h, http.MethodPost, destCandidatesPath+"/"+candidates(t, h, "")["a"].ID+"/publish", "")
	if rr := groupCall(t, h, http.MethodDelete, destSourcesPath+"/"+src.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	var dests, cands int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_destinations`).Scan(&dests)
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_dest_candidates`).Scan(&cands)
	if dests != 1 || cands != 0 {
		t.Fatalf("destinations=%d candidates=%d", dests, cands)
	}
}

func TestDestSourceTypesListsProxmoxWithItsSecretField(t *testing.T) {
	_, h, _ := destTestEnv(t)
	rr := groupCall(t, h, http.MethodGet, destSourcesPath+"/types", "")
	var out struct {
		Types []struct {
			Type   string `json:"type"`
			Fields []struct {
				Key    string `json:"key"`
				Secret bool   `json:"secret"`
			} `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Types) == 0 {
		t.Fatalf("types: %v %s", err, rr.Body.String())
	}
	found := false
	for _, ty := range out.Types {
		for _, f := range ty.Fields {
			if ty.Type == "proxmox" && f.Key == "token_secret" && f.Secret {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("proxmox.token_secret doit être déclaré secret")
	}
}

func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
