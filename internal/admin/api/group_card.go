// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Fiches des groupes HA (ADR 0014, section 3). L'Admin déclare la composition et les domaines de chaque groupe ; il en
// tire une fiche versionnée qu'il pousse à chaque membre. Les membres la gardent, la rattrapent entre eux et la
// servent à un Admin qui se reconstitue (RecoverArchitecture).

// GroupCardPusher pousse la fiche d'un groupe à une passerelle.
type GroupCardPusher interface {
	PushGroupCard(ctx context.Context, edgeName string, card edgews.GroupCard)
}

// BuildGroupCard assemble la fiche d'un groupe, sans version : la composition, et les domaines que ses membres portent.
// tokenNames donne le nom de la passerelle de chaque jeton : le domaine désigne sa passerelle d'entrée par son jeton.
func BuildGroupCard(groups GroupResolver, domains []archstore.DomainEntry, tokenNames map[string]string, group string) edgews.GroupCard {
	card := edgews.GroupCard{Group: group}
	ids := map[string]bool{}
	for _, n := range groups.GroupMembers(group) {
		card.Members = append(card.Members, edgews.CardMember{ID: n.ID, Name: n.Name, Endpoint: n.ControlEndpoint()})
		ids[n.ID], ids[n.Name] = true, true
	}
	sort.Slice(card.Members, func(i, j int) bool { return card.Members[i].ID < card.Members[j].ID })
	for _, d := range domains {
		if !ids[d.EdgeID] && !ids[tokenNames[d.EdgeID]] && d.EdgeID != haEntryPrefix+group {
			continue // ni un membre, ni le groupe lui-même ("ha:<groupe>")
		}
		card.Domains = append(card.Domains, edgews.CardDomain{
			ID: d.ID, Domain: d.Domain, EdgeID: d.EdgeID, DNSProvider: d.DNSProvider, DNSCredentials: d.DNSCredentials,
			CertMethod: d.CertMethod, DelegatedToEdgeID: d.DelegatedToEdgeID, DelegatedEndpoint: d.DelegatedEndpoint,
			DelegationMode: d.DelegationMode, EdgeName: tokenNames[d.EdgeID], DelegatedToName: tokenNames[d.DelegatedToEdgeID],
		})
	}
	sort.Slice(card.Domains, func(i, j int) bool { return card.Domains[i].Domain < card.Domains[j].Domain })
	return card
}

func groupCardHash(card edgews.GroupCard) string {
	card.Version = 0
	b, _ := json.Marshal(card)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GroupCardSync tient les fiches à jour : quand le contenu d'un groupe change, la version augmente et la fiche est
// poussée à chaque membre.
type GroupCardSync struct {
	DB     *sql.DB
	Arch   *archstore.Store
	Groups GroupResolver
	Pusher GroupCardPusher
	Log    *slog.Logger

	mu sync.Mutex
}

// tokenNames : le nom de la passerelle de chaque jeton actif.
func (g *GroupCardSync) tokenNames(ctx context.Context) map[string]string {
	out := map[string]string{}
	rows, err := g.DB.QueryContext(ctx, `SELECT id, node_name FROM tokens WHERE role='edge' AND revoked=0`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			out[id] = name
		}
	}
	return out
}

func (g *GroupCardSync) domains(ctx context.Context) []archstore.DomainEntry {
	list, err := archstore.DomainsFromDB(ctx, g.DB)
	if err != nil {
		return nil
	}
	return list
}

// Sync recalcule la fiche de chaque groupe, incrémente la version de celles dont le contenu a changé et les pousse.
func (g *GroupCardSync) Sync(ctx context.Context) {
	if g == nil || g.Arch == nil || g.Groups == nil || g.DB == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	names, byGroup := g.Groups.Groups()
	domains, tokens := g.domains(ctx), g.tokenNames(ctx)
	for _, name := range names {
		card := BuildGroupCard(g.Groups, domains, tokens, name)
		hash := groupCardHash(card)
		version, stored := g.Arch.GroupCardVersion(name)
		switch {
		case version > 0 && stored == hash:
			continue
		case version > 0 && stored == "":
			// Fiche reprise d'une passerelle : son contenu est celui qu'on vient de reconstituer, la version ne bouge pas.
		default:
			version++
		}
		if err := g.Arch.SetGroupCard(name, version, hash); err != nil {
			g.Log.Warn("ha: version de la fiche non retenue", "group", name, "err", err)
			continue
		}
		card.Version = version
		g.Log.Info("ha: fiche du groupe mise à jour", "group", name, "version", version, "membres", len(card.Members), "domaines", len(card.Domains))
		if g.Pusher != nil {
			for _, n := range byGroup[name] {
				g.Pusher.PushGroupCard(ctx, n.Name, card)
			}
		}
	}
}

// CardFor rend la fiche en vigueur du groupe de la passerelle, pour la lui pousser quand elle se connecte.
func (g *GroupCardSync) CardFor(ctx context.Context, edgeName string) (edgews.GroupCard, bool) {
	if g == nil || g.Arch == nil || g.Groups == nil {
		return edgews.GroupCard{}, false
	}
	group := g.Groups.GroupOf(edgeName)
	if group == "" {
		return edgews.GroupCard{}, false
	}
	version, stored := g.Arch.GroupCardVersion(group)
	card := BuildGroupCard(g.Groups, g.domains(ctx), g.tokenNames(ctx), group)
	if version == 0 || stored != groupCardHash(card) {
		return edgews.GroupCard{}, false // pas encore calculée ou modifiée depuis : Sync la pousse avec sa nouvelle version
	}
	card.Version = version
	return card, true
}
