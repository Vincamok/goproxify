// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

// Kind est le genre d'une entrée du référentiel. L'étape 1 de l'ADR 0023 produit les chemins et les User-Agent ;
// les autres genres (empreinte TLS, forme de charge, suite de chemins) viennent à l'étape 5.
type Kind string

const (
	KindPath Kind = "path"
	KindUA   Kind = "ua"
)

// Status est l'état d'une entrée. L'étape 1 ne pose que candidate et rejected ; detect et enforce arrivent à l'étape 2.
type Status string

const (
	StatusCandidate Status = "candidate"
	StatusRejected  Status = "rejected"
)

// OriginLocal : entrée produite par le mineur de cette installation.
const OriginLocal = "local"

// LiftUnmeasured : le lift d'une entrée dont le trafic légitime n'est pas mesurable (les lignes d'accès des
// passerelles ne portent pas le User-Agent) ; elle ne pourra pas être promue tant qu'elle ne l'est pas.
const LiftUnmeasured = -1.0

// Entry est une entrée du référentiel avec ses preuves : jamais d'IP, d'hôte ni de valeur de paramètre.
type Entry struct {
	Kind        Kind      `json:"kind"`
	Value       string    `json:"value"`
	Family      Family    `json:"family"`
	DistinctIPs int       `json:"distinct_ips"`
	Days        int       `json:"days"`
	Hits        int       `json:"hits"`
	CleanHits   int64     `json:"clean_hits"`
	Lift        float64   `json:"lift"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Status      Status    `json:"status"`
	Origin      string    `json:"origin"`
	Sample      string    `json:"sample,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store range les dossiers et les entrées dans la base de l'Admin.
type Store struct{ DB *sql.DB }

// Migrate crée les tables.
func Migrate(db *sql.DB) error {
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS attack_dossiers (
			ip        TEXT NOT NULL,
			banned_at TEXT NOT NULL,
			source    TEXT NOT NULL DEFAULT '',
			profile   TEXT NOT NULL DEFAULT '',
			requests  INTEGER NOT NULL DEFAULT 0,
			data      TEXT NOT NULL,
			built_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (ip, banned_at)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attack_dossiers_banned ON attack_dossiers (banned_at)`,
		`CREATE TABLE IF NOT EXISTS attack_entries (
			kind         TEXT NOT NULL,
			value        TEXT NOT NULL,
			family       TEXT NOT NULL DEFAULT '',
			distinct_ips INTEGER NOT NULL DEFAULT 0,
			days         INTEGER NOT NULL DEFAULT 0,
			hits         INTEGER NOT NULL DEFAULT 0,
			clean_hits   INTEGER NOT NULL DEFAULT 0,
			lift         REAL NOT NULL DEFAULT -1,
			first_seen   TEXT NOT NULL DEFAULT '',
			last_seen    TEXT NOT NULL DEFAULT '',
			status       TEXT NOT NULL DEFAULT 'candidate',
			origin       TEXT NOT NULL DEFAULT 'local',
			sample       TEXT NOT NULL DEFAULT '',
			updated_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (kind, value)
		)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// SaveDossier écrit (ou remplace) le dossier d'un ban.
func (s *Store) SaveDossier(ctx context.Context, d Dossier) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	profile := string(ProfileUnclassified)
	if len(d.Profiles) > 0 {
		profile = string(d.Profiles[0].Profile)
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT OR REPLACE INTO attack_dossiers (ip, banned_at, source, profile, requests, data, built_at) VALUES (?,?,?,?,?,?,?)`,
		d.IP, sqltime.Format(d.BannedAt), d.Source, profile, d.Requests, string(raw), sqltime.Format(time.Now()))
	return err
}

// HasDossier dit si le ban (IP, date) a déjà son dossier.
func (s *Store) HasDossier(ctx context.Context, ip string, at time.Time) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM attack_dossiers WHERE ip=? AND banned_at=?`, ip, sqltime.Format(at)).Scan(&n)
	return n > 0, err
}

// DossierFilter borne une liste de dossiers.
type DossierFilter struct {
	Profile string
	IP      string
	Since   time.Time
	Limit   int
	Offset  int
}

func (f DossierFilter) where() (string, []any) {
	var c []string
	var a []any
	if f.Profile != "" {
		c, a = append(c, "profile = ?"), append(a, f.Profile)
	}
	if f.IP != "" {
		c, a = append(c, "ip = ?"), append(a, f.IP)
	}
	if !f.Since.IsZero() {
		c, a = append(c, "banned_at >= ?"), append(a, sqltime.Format(f.Since))
	}
	if len(c) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(c, " AND "), a
}

// Dossiers liste les dossiers, du plus récent au plus ancien, et leur nombre total.
func (s *Store) Dossiers(ctx context.Context, f DossierFilter) ([]Dossier, int, error) {
	where, args := f.where()
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM attack_dossiers`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT data FROM attack_dossiers`+where+` ORDER BY banned_at DESC, ip LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Dossier{}
	for rows.Next() {
		var raw string
		var d Dossier
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &d) == nil {
			out = append(out, d)
		}
	}
	return out, total, rows.Err()
}

// DeleteDossiers efface les dossiers d'une IP (effacement RGPD, retrait d'une adresse).
func (s *Store) DeleteDossiers(ctx context.Context, ip string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM attack_dossiers WHERE ip=?`, ip)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeDossiersBefore supprime les dossiers des bans plus anciens que t (rétention des bans).
func (s *Store) PurgeDossiersBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM attack_dossiers WHERE banned_at < ?`, sqltime.Format(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// EntryFilter borne une liste d'entrées.
type EntryFilter struct {
	Kind   string
	Family string
	Status string
	Limit  int
	Offset int
}

// Entries liste les entrées : les mieux étayées d'abord (IP distinctes, puis passages).
func (s *Store) Entries(ctx context.Context, f EntryFilter) ([]Entry, int, error) {
	var c []string
	var a []any
	for col, v := range map[string]string{"kind": f.Kind, "family": f.Family, "status": f.Status} {
		if v != "" {
			c, a = append(c, col+" = ?"), append(a, v)
		}
	}
	where := ""
	if len(c) > 0 {
		where = " WHERE " + strings.Join(c, " AND ")
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM attack_entries`+where, a...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT kind, value, family, distinct_ips, days, hits, clean_hits, lift, first_seen, last_seen, status, origin, sample, updated_at
		 FROM attack_entries`+where+` ORDER BY distinct_ips DESC, hits DESC, value LIMIT ? OFFSET ?`, append(a, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var kind, family, status, first, last, updated string
		if err := rows.Scan(&kind, &e.Value, &family, &e.DistinctIPs, &e.Days, &e.Hits, &e.CleanHits, &e.Lift, &first, &last, &status, &e.Origin, &e.Sample, &updated); err != nil {
			return nil, 0, err
		}
		e.Kind, e.Family, e.Status = Kind(kind), Family(family), Status(status)
		e.FirstSeen, _ = sqltime.Parse(first)
		e.LastSeen, _ = sqltime.Parse(last)
		e.UpdatedAt, _ = sqltime.Parse(updated)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// upsertEntry écrit une entrée du mineur sans toucher à son état : un rejet de l'administrateur survit au recalcul.
func (s *Store) upsertEntry(ctx context.Context, e Entry) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO attack_entries (kind, value, family, distinct_ips, days, hits, clean_hits, lift, first_seen, last_seen, status, origin, sample, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT (kind, value) DO UPDATE SET family=excluded.family, distinct_ips=excluded.distinct_ips, days=excluded.days,
		   hits=excluded.hits, clean_hits=excluded.clean_hits, lift=excluded.lift, first_seen=excluded.first_seen,
		   last_seen=excluded.last_seen, sample=excluded.sample, updated_at=excluded.updated_at`,
		string(e.Kind), e.Value, string(e.Family), e.DistinctIPs, e.Days, e.Hits, e.CleanHits, e.Lift,
		sqltime.Format(e.FirstSeen), sqltime.Format(e.LastSeen), string(StatusCandidate), OriginLocal, e.Sample, sqltime.Format(time.Now()))
	return err
}

// dropStale retire les candidates locales d'un genre que le dernier calcul ne retient plus ; les entrées rejetées
// restent, c'est la mémoire de la décision.
func (s *Store) dropStale(ctx context.Context, kind Kind, keep map[string]struct{}) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT value FROM attack_entries WHERE kind=? AND status=? AND origin=?`, string(kind), string(StatusCandidate), OriginLocal)
	if err != nil {
		return 0, err
	}
	var drop []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			if _, ok := keep[v]; !ok {
				drop = append(drop, v)
			}
		}
	}
	rows.Close()
	for _, v := range drop {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM attack_entries WHERE kind=? AND value=?`, string(kind), v); err != nil {
			return 0, err
		}
	}
	return len(drop), nil
}

// ErrBadStatus : un état que l'étape 1 ne sait pas poser à la main.
var ErrBadStatus = errors.New("état inconnu : candidate ou rejected attendu")

// ErrNotFound : aucune entrée pour ce genre et cette valeur.
var ErrNotFound = errors.New("entrée introuvable")

// SetStatus rejette une entrée ou la remet en candidate.
func (s *Store) SetStatus(ctx context.Context, kind Kind, value string, st Status) error {
	if st != StatusCandidate && st != StatusRejected {
		return ErrBadStatus
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE attack_entries SET status=?, updated_at=? WHERE kind=? AND value=?`, string(st), sqltime.Format(time.Now()), string(kind), value)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Summary compte ce que contient le référentiel.
type Summary struct {
	Dossiers    int            `json:"dossiers"`
	Profiles    map[string]int `json:"profiles"`
	Entries     map[string]int `json:"entries_by_status"`
	Families    map[string]int `json:"entries_by_family"`
	LastDossier time.Time      `json:"last_dossier_at,omitempty"`
}

// Summary rend les totaux du référentiel.
func (s *Store) Summary(ctx context.Context) (Summary, error) {
	sum := Summary{Profiles: map[string]int{}, Entries: map[string]int{}, Families: map[string]int{}}
	count := func(q string, into map[string]int) error {
		rows, err := s.DB.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			into[k] = n
		}
		return rows.Err()
	}
	if err := count(`SELECT profile, COUNT(*) FROM attack_dossiers GROUP BY profile`, sum.Profiles); err != nil {
		return sum, err
	}
	for _, n := range sum.Profiles {
		sum.Dossiers += n
	}
	if err := count(`SELECT status, COUNT(*) FROM attack_entries GROUP BY status`, sum.Entries); err != nil {
		return sum, err
	}
	if err := count(`SELECT family, COUNT(*) FROM attack_entries GROUP BY family`, sum.Families); err != nil {
		return sum, err
	}
	var last sql.NullString
	if err := s.DB.QueryRowContext(ctx, `SELECT MAX(built_at) FROM attack_dossiers`).Scan(&last); err == nil && last.Valid {
		sum.LastDossier, _ = sqltime.Parse(last.String)
	}
	return sum, nil
}
