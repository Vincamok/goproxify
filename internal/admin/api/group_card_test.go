// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

type cardPusher struct {
	mu   sync.Mutex
	sent map[string][]edgews.GroupCard
}

func (p *cardPusher) PushGroupCard(_ context.Context, edge string, card edgews.GroupCard) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sent == nil {
		p.sent = map[string][]edgews.GroupCard{}
	}
	p.sent[edge] = append(p.sent[edge], card)
}

func addDomain(t *testing.T, db *sql.DB, id, domain, edgeID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO domains(id, domain, edge_id, dns_provider, dns_credentials, cert_method) VALUES(?,?,?,?,?,?)`,
		id, domain, edgeID, "ovh", `{"app_key":"k"}`, "dns"); err != nil {
		t.Fatal(err)
	}
}

func cardSync(t *testing.T) (*api.GroupCardSync, *cardPusher, *archstore.Store, *sql.DB) {
	t.Helper()
	db, store, groups := portalFixture(t)
	for _, tok := range [][2]string{{"tok-f", "frontal"}, {"tok-b", "backup"}, {"tok-s", "seul"}} {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?, ?, 'edge', ?, 'operator')`,
			tok[0], "secret-"+tok[0], tok[1]); err != nil {
			t.Fatal(err)
		}
	}
	p := &cardPusher{}
	return &api.GroupCardSync{DB: db, Arch: store, Groups: groups, Pusher: p, Log: slog.Default()}, p, store, db
}

// Le premier passage donne la version 1 à la fiche de chaque groupe déclaré et la pousse à chaque membre. Sans changement,
// rien ne repart.
func TestGroupCardIsVersionedAndPushedOnChangeOnly(t *testing.T) {
	g, p, store, db := cardSync(t)
	ctx := context.Background()
	addDomain(t, db, "d1", "app.example.fr", "tok-f")
	addDomain(t, db, "d2", "ailleurs.example.fr", "tok-s") // une passerelle sans groupe déclaré n'a pas de fiche

	g.Sync(ctx)
	if len(p.sent["frontal"]) != 1 || len(p.sent["backup"]) != 1 || len(p.sent["seul"]) != 0 {
		t.Fatalf("chaque membre du groupe déclaré reçoit sa fiche : %v", p.sent)
	}
	c := p.sent["frontal"][0]
	if c.Group != "ha-1" || c.Version != 1 || len(c.Members) != 2 || len(c.Domains) != 1 || c.Domains[0].Domain != "app.example.fr" || c.Domains[0].DNSCredentials != `{"app_key":"k"}` || c.Domains[0].EdgeName != "frontal" {
		t.Fatalf("fiche de ha-1 : %+v", c)
	}

	g.Sync(ctx)
	if len(p.sent["frontal"]) != 1 {
		t.Fatal("contenu inchangé : rien n'est repoussé")
	}

	addDomain(t, db, "d3", "neuf.example.fr", "tok-b")
	addDomain(t, db, "d4", "groupe.example.fr", "ha:ha-1")
	g.Sync(ctx)
	if len(p.sent["frontal"]) != 2 || p.sent["frontal"][1].Version != 2 || len(p.sent["frontal"][1].Domains) != 3 {
		t.Fatalf("un domaine ajouté fait passer ha-1 à la version 2 : %+v", p.sent["frontal"])
	}
	if v, _ := store.GroupCardVersion("ha-1"); v != 2 {
		t.Fatalf("version retenue dans architecture.json : %d", v)
	}
}

// Une passerelle qui se connecte reçoit la fiche en vigueur ; tant que la fiche n'est pas à jour, Sync la pousse.
func TestGroupCardForAConnectingMember(t *testing.T) {
	g, _, _, db := cardSync(t)
	ctx := context.Background()
	if _, ok := g.CardFor(ctx, "frontal"); ok {
		t.Fatal("aucune fiche avant le premier calcul")
	}
	g.Sync(ctx)
	c, ok := g.CardFor(ctx, "backup")
	if !ok || c.Version != 1 || c.Group != "ha-1" {
		t.Fatalf("fiche en vigueur : %+v %v", c, ok)
	}
	addDomain(t, db, "d1", "app.example.fr", "tok-f")
	if _, ok := g.CardFor(ctx, "backup"); ok {
		t.Fatal("contenu modifié depuis : Sync pousse la nouvelle version")
	}
}

// Reconstitution : un Admin neuf retrouve groupes, membres et domaines des fiches ; ce qu'il connaît déjà reste tel quel,
// et sa version de fiche repart de la plus haute.
func TestArchitectureRecoversFromGroupCards(t *testing.T) {
	db, store, groups := portalFixture(t)
	_ = groups
	// Le nouvel Admin a appairé frontal sous un jeton qui n'est pas celui de l'ancien.
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES ('tok-new', 'secret-new', 'edge', 'frontal', 'operator')`); err != nil {
		t.Fatal(err)
	}
	// fichier vierge : on repart de zéro
	fresh := archstore.New(t.TempDir())
	h := &api.ArchitectureHandler{DB: db, Log: slog.Default(), Store: fresh,
		FetchCards: func(context.Context, []string) ([]edgews.GroupCard, []string) {
			old := edgews.GroupCard{Group: "ha-1", Version: 3, Members: []edgews.CardMember{{ID: "dn_f", Name: "frontal"}}}
			cur := edgews.GroupCard{Group: "ha-1", Version: 5,
				Members: []edgews.CardMember{{ID: "dn_f", Name: "frontal", Endpoint: "https://a:8443"}, {ID: "dn_b", Name: "backup"}},
				Domains: []edgews.CardDomain{{ID: "d1", Domain: "app.example.fr", EdgeID: "tok-old", EdgeName: "frontal", DNSProvider: "ovh", DNSCredentials: `{"app_key":"k"}`, CertMethod: "dns"}}}
			return []edgews.GroupCard{old, cur}, []string{"lointain : timeout"}
		}}
	_ = store

	rec := do(h, http.MethodPost, "/api/v1/architecture/recover", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("recover: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Cards       int      `json:"cards"`
		Unreachable []string `json:"unreachable"`
		Added       struct {
			Nodes, Domains int
		} `json:"added"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Cards != 2 || len(out.Unreachable) != 1 || out.Added.Nodes != 2 || out.Added.Domains != 1 {
		t.Fatalf("rapport : %+v", out)
	}
	names, members := fresh.Groups()
	if len(names) != 1 || names[0] != "ha-1" || len(members["ha-1"]) != 2 {
		t.Fatalf("groupe reconstitué : %v %v", names, members)
	}
	if v, _ := fresh.GroupCardVersion("ha-1"); v != 5 {
		t.Fatalf("la version la plus haute est reprise : %d", v)
	}
	arch, _ := fresh.Get()
	if len(arch.Domains) != 1 || arch.Domains[0].DNSCredentials != `{"app_key":"k"}` || arch.Domains[0].EdgeID != "tok-new" {
		t.Fatalf("domaine reconstitué : %+v", arch.Domains)
	}

	// Rejouée : rien n'est ajouté de plus, rien n'est écrasé.
	rec = do(h, http.MethodPost, "/api/v1/architecture/recover", `{}`)
	if rec.Code != http.StatusOK || !jsonContains(rec.Body.String(), `"nodes":0`) {
		t.Fatalf("rejeu : %d %s", rec.Code, rec.Body.String())
	}
}

func jsonContains(body, sub string) bool { return len(body) > 0 && (indexOf(body, sub) >= 0) }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Après une reconstitution, la fiche reprise d'une passerelle garde sa version tant que le contenu est celui qu'elle
// portait : la première passe adopte son empreinte sans la faire monter.
func TestGroupCardRecoveredVersionDoesNotBumpWhenContentMatches(t *testing.T) {
	db, store, groups := portalFixture(t)
	addDomain(t, db, "d1", "app.example.fr", "dn_f") // un domaine désigné par l'identifiant du nœud est un membre aussi
	built := api.BuildGroupCard(groups, mustDomains(t, db), nil, "ha-1")
	if err := store.SetGroupCard("ha-1", 7, ""); err != nil {
		t.Fatal(err)
	}
	p := &cardPusher{}
	g := &api.GroupCardSync{DB: db, Arch: store, Groups: groups, Pusher: p, Log: slog.Default()}
	g.Sync(context.Background())
	if v, _ := store.GroupCardVersion("ha-1"); v != 7 {
		t.Fatalf("version reprise inchangée : %d", v)
	}
	if got := p.sent["frontal"]; len(got) != 1 || got[0].Version != 7 || len(got[0].Members) != len(built.Members) {
		t.Fatalf("la fiche v7 est poussée : %+v", got)
	}
}

func mustDomains(t *testing.T, db *sql.DB) []archstore.DomainEntry {
	t.Helper()
	list, err := archstore.DomainsFromDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return list
}
