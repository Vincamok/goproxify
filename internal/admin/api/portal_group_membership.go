// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Composition des groupes HA (ADR 0014). L'Admin ne reçoit pas de signal quand un membre quitte un groupe : la liste des
// membres et la clé du groupe n'étaient poussées qu'à l'édition du portail ou à la reconnexion d'une passerelle, si bien
// que les membres restants gardaient le nom du membre sorti dans leur liste de pairs, et sa clé.
//
// Ce réconciliateur compare la composition déclarée dans l'architecture à la dernière connue :
//   - un membre sorti : la clé du groupe est renouvelée et poussée aux membres restants avec la liste à jour ; le membre
//     sorti reçoit la configuration de son propre groupe (sans champs HA tant que le groupe d'un membre n'existe pas) ;
//   - un membre ajouté : la liste à jour est poussée à tous, sans changer la clé.
//
// Il ne réagit qu'à une composition déclarée : un membre qui ne répond pas reste membre, avec sa clé.

const (
	settingGroupMembersPrefix = "ha.members."
	settingKnownGroups        = "ha.members.groups"
	// dissolveAfter : un groupe n'est tenu pour dissous qu'après avoir manqué à autant de passages de suite.
	dissolveAfter = 2
)

// EdgeTokenRotator renouvelle les jetons que l'Admin a pour des passerelles.
type EdgeTokenRotator interface {
	RotateEdgeTokens(ctx context.Context, refs []string)
}

// GroupMembership suit la composition des groupes HA et renouvelle la clé d'un groupe quand un membre le quitte.
type GroupMembership struct {
	DB     *sql.DB
	Groups GroupResolver
	Pusher PortalPusher
	Cards  *GroupCardSync // fiches de groupe, tenues à jour à chaque passage ; nil = désactivé
	// Tokens renouvelle les jetons des passerelles restantes quand un membre sort : il connaît ceux de ses pairs. nil = désactivé.
	Tokens EdgeTokenRotator
	Log    *slog.Logger

	missing map[string]int
}

// Run réconcilie toutes les every jusqu'à l'annulation du contexte.
func (m *GroupMembership) Run(ctx context.Context, every time.Duration) {
	m.Reconcile(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Reconcile(ctx)
		}
	}
}

// members : identifiant du nœud → nom. L'identifiant sert à comparer (un renommage n'est pas une sortie), le nom à pousser.
type members map[string]string

func (m *GroupMembership) load(group string) (members, bool) {
	raw := admindb.GetSetting(m.DB, settingGroupMembersPrefix+group, "")
	if raw == "" {
		return nil, false
	}
	var out members
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil, false
	}
	return out, true
}

func (m *GroupMembership) store(group string, cur members) {
	b, _ := json.Marshal(cur)
	if err := admindb.SetSetting(m.DB, settingGroupMembersPrefix+group, string(b)); err != nil {
		m.Log.Warn("ha: composition du groupe non retenue", "group", group, "err", err)
	}
}

func (m *GroupMembership) knownGroups() []string {
	var out []string
	_ = json.Unmarshal([]byte(admindb.GetSetting(m.DB, settingKnownGroups, "[]")), &out)
	return out
}

func (m *GroupMembership) storeKnownGroups(names []string) {
	sort.Strings(names)
	b, _ := json.Marshal(names)
	_ = admindb.SetSetting(m.DB, settingKnownGroups, string(b))
}

// Reconcile compare la composition de chaque groupe à la dernière connue et agit sur les changements.
func (m *GroupMembership) Reconcile(ctx context.Context) {
	if m.Groups == nil || m.DB == nil {
		return
	}
	defer m.Cards.Sync(ctx)
	names, byGroup := m.Groups.Groups()
	if m.missing == nil {
		m.missing = map[string]int{}
	}

	seen := map[string]bool{}
	for _, g := range names {
		seen[g] = true
		delete(m.missing, g)
		cur := members{}
		for _, n := range byGroup[g] {
			cur[n.ID] = n.Name
		}
		prev, had := m.load(g)
		if !had {
			m.store(g, cur) // premier passage : on retient, sans rotation rétroactive
			continue
		}
		var removed, added []string
		for id := range prev {
			if _, ok := cur[id]; !ok {
				removed = append(removed, id)
			}
		}
		for id := range cur {
			if _, ok := prev[id]; !ok {
				added = append(added, id)
			}
		}
		if len(removed) == 0 && len(added) == 0 {
			continue
		}
		if len(removed) > 0 {
			if err := rotateGroupKey(m.DB, g); err != nil {
				m.Log.Error("ha: clé du groupe non renouvelée, composition non retenue", "group", g, "err", err)
				continue // retenté au prochain passage
			}
			m.Log.Info("ha: membre sorti du groupe, clé du groupe renouvelée", "group", g, "sortis", len(removed))
		}
		m.store(g, cur)
		if len(removed) > 0 && m.Tokens != nil {
			names := make([]string, 0, len(cur))
			for _, name := range cur {
				names = append(names, name)
			}
			m.Tokens.RotateEdgeTokens(ctx, names)
			m.Log.Info("ha: jetons des membres restants renouvelés après la sortie d'un membre", "group", g, "membres", len(names))
		}
		for _, name := range cur {
			m.push(ctx, name)
		}
		for _, id := range removed {
			m.push(ctx, prev[id]) // sa propre configuration, plus celle du groupe
		}
	}

	// Un groupe qui n'est plus déclaré : ses anciens membres reçoivent leur propre configuration. Une seule absence
	// ne suffit pas (une lecture de l'architecture qui échoue ressemble à un groupe disparu).
	known := m.knownGroups()
	next := make([]string, 0, len(names))
	next = append(next, names...)
	for _, g := range known {
		if seen[g] {
			continue
		}
		if len(names) == 0 {
			next = append(next, g) // aucun groupe lu du tout : on ne conclut rien
			continue
		}
		m.missing[g]++
		if m.missing[g] < dissolveAfter {
			next = append(next, g)
			continue
		}
		if prev, ok := m.load(g); ok {
			for _, name := range prev {
				m.push(ctx, name)
			}
		}
		_ = admindb.SetSetting(m.DB, settingGroupMembersPrefix+g, "")
		delete(m.missing, g)
		m.Log.Info("ha: groupe dissous, ses membres reçoivent leur propre configuration", "group", g)
	}
	m.storeKnownGroups(next)
}

func (m *GroupMembership) push(ctx context.Context, edgeName string) {
	if m.Pusher == nil || edgeName == "" {
		return
	}
	m.Pusher.PushPortal(ctx, edgeName, BuildPortalPayload(m.DB, m.Groups, edgeName))
}

// rotateGroupKey remplace la clé de réplication du groupe par une nouvelle, scellée dans la base. L'ancienne n'est pas
// gardée : elle ne chiffre que des échanges en cours, rien qui soit stocké.
func rotateGroupKey(db *sql.DB, group string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("clé aléatoire : %w", err)
	}
	plain := hex.EncodeToString(raw)
	return admindb.SetSetting(db, settingPortalHAKeyPrefix+groupScopePrefix+group, auth.SealNodeToken(plain))
}
