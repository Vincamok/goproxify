// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/destsync"
	"github.com/vincamok/goproxify/internal/modules"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// Sources de destinations du portail (ADR 0024). L'Admin garde la configuration des sources (secrets scellés) et la pousse
// à la passerelle avec celle du portail ; la passerelle interroge les fournisseurs et remet leur inventaire, que l'Admin
// range en candidates. Rien n'est visible des utilisateurs avant la publication d'une candidate.

// États d'une candidate.
const (
	CandNew       = "new"       // vue chez le fournisseur, pas encore publiée
	CandPublished = "published" // une destination du catalogue la représente
	CandIgnored   = "ignored"   // écartée par un opérateur
	CandMissing   = "missing"   // publiée, mais absente du dernier inventaire réussi
)

// DestSource est une source configurée.
type DestSource struct {
	ID           string         `json:"id"`
	EdgeName     string         `json:"edge_name"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	Config       map[string]any `json:"config"`
	IntervalS    int            `json:"interval_s"`
	Enabled      bool           `json:"enabled"`
	ExtraTags    []string       `json:"extra_tags"`
	AutoPublish  bool           `json:"auto_publish"`
	Status       string         `json:"status"` // "" (jamais lue) | ok | error
	StatusMsg    string         `json:"status_msg,omitempty"`
	LastSyncAt   string         `json:"last_sync_at,omitempty"`
	MachineCount int            `json:"machine_count"`
	// Candidates : nombre de candidates par état, pour la liste.
	Candidates map[string]int `json:"candidates,omitempty"`
}

// DestCandidate est une machine vue par une source.
type DestCandidate struct {
	ID         string            `json:"id"`
	SourceID   string            `json:"source_id"`
	SourceName string            `json:"source_name,omitempty"`
	SourceType string            `json:"source_type,omitempty"`
	EdgeName   string            `json:"edge_name"`
	ExternalID string            `json:"external_id"`
	Name       string            `json:"name"`
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	Tags       []string          `json:"tags"`
	Running    bool              `json:"running"`
	Detail     map[string]string `json:"detail,omitempty"`
	State      string            `json:"state"`
	DestID     string            `json:"destination_id,omitempty"`
	FirstSeen  string            `json:"first_seen"`
	LastSeen   string            `json:"last_seen"`
}

const destSourceCols = `id, edge_name, type, name, config_enc, interval_s, enabled, extra_tags_json, auto_publish,
	status, status_msg, last_sync_at, machine_count`

func scanDestSource(s scanner) (DestSource, error) {
	var d DestSource
	var enc, extra string
	var en, auto int
	if err := s.Scan(&d.ID, &d.EdgeName, &d.Type, &d.Name, &enc, &d.IntervalS, &en, &extra, &auto,
		&d.Status, &d.StatusMsg, &d.LastSyncAt, &d.MachineCount); err != nil {
		return d, err
	}
	d.Enabled, d.AutoPublish = en != 0, auto != 0
	_ = json.Unmarshal([]byte(extra), &d.ExtraTags)
	d.ExtraTags = normalizeTags(d.ExtraTags)
	d.Config = map[string]any{}
	if plain, err := auth.OpenNodeToken(enc); err == nil && plain != "" {
		_ = json.Unmarshal([]byte(plain), &d.Config)
	}
	return d, nil
}

func sealDestConfig(cfg map[string]any) string {
	raw, _ := json.Marshal(cfg)
	return auth.SealNodeToken(string(raw))
}

// masked retourne la source telle que l'API la rend : secrets remplacés par le masque.
func (d DestSource) masked() DestSource {
	if man, ok := destsync.ManifestOf(d.Type); ok {
		d.Config = man.Mask(d.Config)
	}
	return d
}

func loadDestSource(db *sql.DB, id string) (DestSource, error) {
	return scanDestSource(db.QueryRow(`SELECT `+destSourceCols+` FROM portal_dest_sources WHERE id=?`, id))
}

func listDestSources(db *sql.DB, scope string) ([]DestSource, error) {
	q := `SELECT ` + destSourceCols + ` FROM portal_dest_sources`
	var rows *sql.Rows
	var err error
	if scope != "" {
		rows, err = db.Query(q+` WHERE edge_name=? ORDER BY name`, scope)
	} else {
		rows, err = db.Query(q + ` ORDER BY edge_name, name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DestSource{}
	for rows.Next() {
		d, err := scanDestSource(rows)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// destSourcesForPush retourne les sources de la portée telles que la passerelle les reçoit, secrets en clair. La liste est
// toujours non nulle : vide, elle retire les sources que la passerelle faisait tourner.
func destSourcesForPush(db *sql.DB, scope string) []destsync.SourceConfig {
	out := []destsync.SourceConfig{}
	list, err := listDestSources(db, scope)
	if err != nil {
		return out
	}
	for _, d := range list {
		out = append(out, destsync.SourceConfig{ID: d.ID, Type: d.Type, Name: d.Name, Enabled: d.Enabled, IntervalS: d.IntervalS, Config: d.Config})
	}
	return out
}

// dbtx est ce que partagent *sql.DB et *sql.Tx.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

const destCandCols = `id, source_id, edge_name, external_id, name, host, port, tags_json, running, detail_json, state, dest_id, first_seen, last_seen`

func scanDestCandidate(s scanner) (DestCandidate, error) {
	var c DestCandidate
	var tags, detail string
	var run int
	if err := s.Scan(&c.ID, &c.SourceID, &c.EdgeName, &c.ExternalID, &c.Name, &c.Host, &c.Port, &tags, &run, &detail, &c.State, &c.DestID, &c.FirstSeen, &c.LastSeen); err != nil {
		return c, err
	}
	c.Running = run != 0
	_ = json.Unmarshal([]byte(tags), &c.Tags)
	c.Tags = normalizeTags(c.Tags)
	_ = json.Unmarshal([]byte(detail), &c.Detail)
	return c, nil
}

// PublishOverrides : ce qu'un opérateur peut corriger en publiant (adresse inconnue du fournisseur, nom, étiquettes en plus).
type PublishOverrides struct {
	Name string   `json:"name"`
	Host string   `json:"host"`
	Port int      `json:"port"`
	Tags []string `json:"tags"`
}

var errNoAddress = errors.New("adresse inconnue : le fournisseur n'en donne pas, la saisir à la publication")

// publishCandidate crée la destination d'une candidate et les relie. Les étiquettes sont celles du fournisseur, celles de la
// source et celles de la publication ; le filtrage par étiquettes de l'utilisateur (R9–R10) les applique ensuite.
func publishCandidate(db dbtx, c DestCandidate, src DestSource, ov PublishOverrides) (string, error) {
	d := PortalDestination{
		ID: uuid.New().String(), EdgeName: c.EdgeName, Kind: "ssh", Name: firstNonEmpty(ov.Name, c.Name),
		Host: firstNonEmpty(ov.Host, c.Host), Port: c.Port, Enabled: true,
		Tags: normalizeTags(append(append(append([]string{}, c.Tags...), src.ExtraTags...), ov.Tags...)),
	}
	if ov.Port > 0 {
		d.Port = ov.Port
	}
	if strings.TrimSpace(d.Host) == "" {
		return "", errNoAddress
	}
	if err := validateDestination(&d); err != nil {
		return "", err
	}
	tags, _ := json.Marshal(d.Tags)
	if _, err := db.Exec(`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port, agent_name, container, tags_json, enabled)
		VALUES (?,?,?,?,?,?,'','',?,1)`, d.ID, d.EdgeName, d.Kind, d.Name, d.Host, d.Port, string(tags)); err != nil {
		return "", err
	}
	// La candidate garde les valeurs du fournisseur : c'est en les comparant à celles de la destination qu'on sait si
	// l'opérateur l'a corrigée à la main (elle ne suit plus alors le fournisseur).
	if _, err := db.Exec(`UPDATE portal_dest_candidates SET state=?, dest_id=? WHERE id=?`, CandPublished, d.ID, c.ID); err != nil {
		return "", err
	}
	return d.ID, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ReconcileResult dit si le catalogue a changé (à pousser aux passerelles) et combien de candidates sont nouvelles.
type ReconcileResult struct {
	CatalogChanged bool
	New            int
}

// reconcileInventory range l'inventaire réussi d'une source dans les candidates (ADR 0024) :
//   - une machine inconnue devient candidate (publiée d'emblée si la source le demande et si son adresse est connue) ;
//   - une machine publiée dont le fournisseur change le nom ou l'adresse suit, sauf champ que l'opérateur a modifié à la main ;
//   - une machine publiée absente de l'inventaire passe en « missing » et sa destination est désactivée, jamais supprimée ;
//   - une machine absente qui n'avait jamais été publiée disparaît de la file.
//
// Elle n'est appelée que pour un inventaire réussi : une panne du fournisseur ne retire donc jamais une destination.
func reconcileInventory(tx dbtx, src DestSource, machines []destsync.Machine, now time.Time) (ReconcileResult, error) {
	var res ReconcileResult
	stamp := sqltime.Format(now)

	existing := map[string]DestCandidate{}
	rows, err := tx.Query(`SELECT `+destCandCols+` FROM portal_dest_candidates WHERE source_id=?`, src.ID)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		if c, err := scanDestCandidate(rows); err == nil {
			existing[c.ExternalID] = c
		}
	}
	rows.Close()

	seen := map[string]bool{}
	for _, m := range machines {
		seen[m.ExternalID] = true
		tags, _ := json.Marshal(normalizeTags(m.Tags))
		detail, _ := json.Marshal(m.Detail)
		port := m.Port
		if port <= 0 {
			port = 22
		}
		running := 0
		if m.Running {
			running = 1
		}
		name := firstNonEmpty(m.Name, m.ExternalID)

		cur, known := existing[m.ExternalID]
		if !known {
			c := DestCandidate{ID: uuid.New().String(), SourceID: src.ID, EdgeName: src.EdgeName, ExternalID: m.ExternalID,
				Name: name, Host: m.Host, Port: port, State: CandNew}
			if _, err := tx.Exec(`INSERT INTO portal_dest_candidates (`+destCandCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				c.ID, c.SourceID, c.EdgeName, c.ExternalID, c.Name, c.Host, c.Port, string(tags), running, string(detail), CandNew, "", stamp, stamp); err != nil {
				return res, err
			}
			res.New++
			if src.AutoPublish && m.Host != "" {
				c.Tags = normalizeTags(m.Tags)
				if _, err := publishCandidate(tx, c, src, PublishOverrides{}); err == nil {
					res.CatalogChanged = true
					res.New--
				}
			}
			continue
		}

		state, destID := cur.State, cur.DestID
		if state == CandPublished || state == CandMissing {
			var enabled int
			var dName, dHost string
			var dPort int
			err := tx.QueryRow(`SELECT name, host, port, enabled FROM portal_destinations WHERE id=?`, cur.DestID).Scan(&dName, &dHost, &dPort, &enabled)
			switch {
			case err == sql.ErrNoRows || cur.DestID == "":
				state, destID = CandNew, "" // la destination a été supprimée à la main
			case err != nil:
				return res, err
			default:
				// La destination suit le fournisseur champ par champ, tant que l'opérateur n'y a pas touché : sa valeur est
				// encore celle que la synchronisation y avait mise (la dernière valeur de la candidate).
				newName, newHost, newPort := dName, dHost, dPort
				if dName == cur.Name && name != cur.Name {
					newName = name
				}
				if dHost == cur.Host && m.Host != "" && m.Host != cur.Host {
					newHost = m.Host
				}
				if dPort == cur.Port && port != cur.Port {
					newPort = port
				}
				if state == CandMissing {
					enabled, state = 1, CandPublished
				}
				if newName != dName || newHost != dHost || newPort != dPort || state != cur.State {
					if _, err := tx.Exec(`UPDATE portal_destinations SET name=?, host=?, port=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
						newName, newHost, newPort, enabled, destID); err != nil {
						return res, err
					}
					res.CatalogChanged = true
				}
			}
		}
		host := m.Host
		if host == "" {
			host = cur.Host // le fournisseur ne la donne pas ce coup-ci : on garde la dernière connue
		}
		if _, err := tx.Exec(`UPDATE portal_dest_candidates SET name=?, host=?, port=?, tags_json=?, running=?, detail_json=?, state=?, dest_id=?, last_seen=? WHERE id=?`,
			name, host, port, string(tags), running, string(detail), state, destID, stamp, cur.ID); err != nil {
			return res, err
		}
	}

	for ext, cur := range existing {
		if seen[ext] {
			continue
		}
		switch cur.State {
		case CandNew, CandIgnored:
			if _, err := tx.Exec(`DELETE FROM portal_dest_candidates WHERE id=?`, cur.ID); err != nil {
				return res, err
			}
		case CandPublished:
			if _, err := tx.Exec(`UPDATE portal_dest_candidates SET state=? WHERE id=?`, CandMissing, cur.ID); err != nil {
				return res, err
			}
			if r, err := tx.Exec(`UPDATE portal_destinations SET enabled=0, updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1`, cur.DestID); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.CatalogChanged = true
				}
			}
		}
	}
	return res, nil
}

// ApplyDestInventory traite l'inventaire qu'une passerelle vient de remettre. Il est ignoré si la source n'existe plus ou si
// la passerelle n'est pas de sa portée (une passerelle sortie d'un groupe peut encore envoyer un dernier état).
func ApplyDestInventory(ctx context.Context, db *sql.DB, log *slog.Logger, g GroupResolver, pusher PortalPusher, node string, inv destsync.Inventory) error {
	src, err := loadDestSource(db, inv.SourceID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if scopeFor(g, node) != src.EdgeName {
		return nil
	}
	now := time.Now().UTC()
	if !inv.OK {
		msg := inv.Error
		if len(msg) > 500 {
			msg = msg[:500]
		}
		_, err := db.ExecContext(ctx, `UPDATE portal_dest_sources SET status='error', status_msg=?, last_sync_at=? WHERE id=?`, msg, sqltime.Format(now), src.ID)
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := reconcileInventory(tx, src, inv.Machines, now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE portal_dest_sources SET status='ok', status_msg='', last_sync_at=?, machine_count=? WHERE id=?`,
		sqltime.Format(now), len(inv.Machines), src.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if res.CatalogChanged && pusher != nil {
		h := &PortalHandler{DB: db, Log: log, Pusher: pusher, Groups: g}
		h.pushScope(ctx, src.EdgeName)
	}
	if res.New > 0 {
		log.Info("portail: nouvelles machines à publier", "source", src.Name, "count", res.New)
	}
	return nil
}

func validateDestSourceConfig(typ string, cfg map[string]any) error {
	man, ok := destsync.ManifestOf(typ)
	if !ok {
		return fmt.Errorf("type de source inconnu : %s", typ)
	}
	if err := man.Validate(cfg); err != nil {
		return err
	}
	_, err := destsync.Build(typ, cfg)
	return err
}

// destSourceManifests : les types disponibles, pour les formulaires, la CLI et le MCP.
func destSourceManifests() []modules.Manifest { return destsync.Manifests() }
