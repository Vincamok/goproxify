// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vincamok/goproxify/internal/admin/importer"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// MaxDestinations borne le nombre de destinations externes.
const MaxDestinations = 10

// staleGrace : retard toléré sur une planification avant de la déclarer manquée.
const staleGrace = time.Hour

// secretDestKeys : clés de configuration jamais renvoyées par l'API.
var secretDestKeys = map[string]bool{"password": true, "secret_key": true}

// Destination est un emplacement externe où chaque snapshot est copié.
type Destination struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Enabled   bool              `json:"enabled"`
	Config    map[string]string `json:"config"`
	Retention int               `json:"retention"` // copies conservées sur cette destination (0 = illimité)
}

// Notifier signale un incident de sauvegarde (branché sur le moteur d'alertes).
type Notifier func(severity, title string, detail map[string]any)

// SetNotifier branche les alertes d'échec et de sauvegarde manquée.
func (s *Scheduler) SetNotifier(n Notifier) { s.notifier = n }

func (s *Scheduler) alert(severity, title string, detail map[string]any) {
	if s.notifier != nil {
		s.notifier(severity, title, detail)
	}
}

// ── Destinations ──────────────────────────────────────────────────────────────

func (s *Scheduler) loadDestinations(onlyEnabled bool) ([]Destination, error) {
	q := `SELECT id, name, type, enabled, config, retention FROM backup_destinations`
	if onlyEnabled {
		q += ` WHERE enabled=1`
	}
	rows, err := s.db.Query(q + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Destination{}
	for rows.Next() {
		var d Destination
		var cfg string
		var en int
		if rows.Scan(&d.ID, &d.Name, &d.Type, &en, &cfg, &d.Retention) != nil {
			continue
		}
		d.Enabled = en == 1
		_ = json.Unmarshal([]byte(cfg), &d.Config)
		if d.Config == nil {
			d.Config = map[string]string{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListDestinations renvoie les destinations, secrets masqués (`<clé>_set` indique qu'un secret existe).
func (s *Scheduler) ListDestinations() ([]Destination, error) {
	ds, err := s.loadDestinations(false)
	for i := range ds {
		ds[i].Config = maskDestConfig(ds[i].Config)
	}
	return ds, err
}

func maskDestConfig(c map[string]string) map[string]string {
	out := make(map[string]string, len(c))
	for k, v := range c {
		if secretDestKeys[k] {
			if v != "" {
				out[k+"_set"] = "true"
			}
			continue
		}
		out[k] = v
	}
	return out
}

func (s *Scheduler) getDestination(id string) (Destination, error) {
	ds, err := s.loadDestinations(false)
	if err != nil {
		return Destination{}, err
	}
	for _, d := range ds {
		if d.ID == id {
			return d, nil
		}
	}
	return Destination{}, sql.ErrNoRows
}

// SaveDestination crée (ID vide) ou met à jour une destination. Un secret vide conserve l'existant.
func (s *Scheduler) SaveDestination(d Destination) (Destination, error) {
	if d.Name == "" {
		return d, errors.New("nom requis")
	}
	if d.Retention < 0 {
		d.Retention = 0
	}
	cfg := map[string]string{}
	for k, v := range d.Config {
		if len(k) > 6 && k[len(k)-4:] == "_set" {
			continue
		}
		cfg[k] = v
	}
	d.Config = cfg
	if d.ID == "" {
		n := 0
		s.db.QueryRow(`SELECT COUNT(*) FROM backup_destinations`).Scan(&n) //nolint:errcheck
		if n >= MaxDestinations {
			return d, fmt.Errorf("%d destinations au plus", MaxDestinations)
		}
		d.ID = uuid.New().String()
	} else if old, err := s.getDestination(d.ID); err == nil {
		for k := range secretDestKeys {
			if d.Config[k] == "" {
				d.Config[k] = old.Config[k]
			}
		}
	}
	if _, err := NewDriver(d); err != nil {
		return d, err
	}
	raw, _ := json.Marshal(d.Config)
	en := 0
	if d.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO backup_destinations (id, name, type, enabled, config, retention) VALUES (?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, enabled=excluded.enabled, config=excluded.config, retention=excluded.retention`,
		d.ID, d.Name, d.Type, en, string(raw), d.Retention)
	d.Config = maskDestConfig(d.Config)
	return d, err
}

// DeleteDestination retire la destination ; les copies déjà déposées ne sont pas supprimées.
func (s *Scheduler) DeleteDestination(id string) error {
	s.db.Exec(`DELETE FROM backup_deliveries WHERE destination_id=?`, id) //nolint:errcheck
	_, err := s.db.Exec(`DELETE FROM backup_destinations WHERE id=?`, id)
	return err
}

// TestDestination écrit, relit puis supprime un petit objet pour valider la configuration.
func (s *Scheduler) TestDestination(ctx context.Context, id string) error {
	d, err := s.getDestination(id)
	if err != nil {
		return errors.New("destination introuvable")
	}
	drv, err := NewDriver(d)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("gpx-test-%d.tmp", time.Now().UnixNano())
	payload := []byte("goproxify backup destination test " + name)
	if err := drv.Put(ctx, name, payload); err != nil {
		return fmt.Errorf("écriture : %w", err)
	}
	defer drv.Delete(ctx, name) //nolint:errcheck
	got, err := drv.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("relecture : %w", err)
	}
	if sha256Hex(got) != sha256Hex(payload) {
		return errors.New("relecture : contenu différent de ce qui a été écrit")
	}
	return nil
}

// ── Vérification ──────────────────────────────────────────────────────────────

// verifyData contrôle un snapshot tel que stocké : somme de contrôle, déchiffrement, format,
// et déchiffrement de la section secrets quand elle existe.
func verifyData(stored []byte, wantSHA string) error {
	if wantSHA != "" && sha256Hex(stored) != wantSHA {
		return errors.New("somme de contrôle différente : snapshot altéré ou corrompu")
	}
	plain, err := openSnapshot(stored)
	if err != nil {
		return fmt.Errorf("déchiffrement : %w", err)
	}
	b, _, err := importer.SummarizeBackup(plain)
	if err != nil {
		return fmt.Errorf("format : %w", err)
	}
	if b.Secrets != "" {
		if _, err := importer.OpenSecretsSummary(b); err != nil {
			return err
		}
	}
	if b.History != "" {
		if _, err := importer.OpenHistorySummary(b); err != nil {
			return err
		}
	}
	return nil
}

// VerifySnapshot relit un snapshot stocké et le contrôle ; l'horodatage de vérification n'est
// posé qu'en cas de succès.
func (s *Scheduler) VerifySnapshot(id string) error {
	var data, sum string
	if err := s.db.QueryRow(`SELECT data, sha256 FROM backup_snapshots WHERE id=?`, id).Scan(&data, &sum); err != nil {
		return errors.New("snapshot introuvable")
	}
	if err := verifyData([]byte(data), sum); err != nil {
		return err
	}
	s.db.Exec(`UPDATE backup_snapshots SET verified_at=?, sha256=CASE WHEN sha256='' THEN ? ELSE sha256 END WHERE id=?`, //nolint:errcheck
		sqltime.Format(time.Now()), sha256Hex([]byte(data)), id)
	return nil
}

// ── Envoi vers les destinations ───────────────────────────────────────────────

func remoteName(id, name string, at time.Time) string {
	return fmt.Sprintf("gpx-%s-%s-%s.snap", at.UTC().Format("20060102T150405Z"), slugify(name), id[:8])
}

// deliver copie un snapshot sur chaque destination active, relit la copie pour la comparer,
// applique la rétention de la destination et signale les échecs.
func (s *Scheduler) deliver(id, name string, data []byte) {
	dests, err := s.loadDestinations(true)
	if err != nil || len(dests) == 0 {
		return
	}
	sum := sha256Hex(data)
	obj := remoteName(id, name, time.Now())
	for _, d := range dests {
		s.run.startDelivery(d.Name)
		derr := s.deliverOne(d, id, obj, sum, data)
		s.run.endDelivery(d.Name)
		msg := ""
		if derr != nil {
			msg = derr.Error()
			s.log.Error("backup: envoi vers la destination échoué", "destination", d.Name, "snapshot", id, "err", derr)
			s.alert("critical", fmt.Sprintf("Sauvegarde : envoi vers « %s » échoué", d.Name),
				map[string]any{"destination": d.Name, "snapshot": name, "message": msg})
		}
		ok := 0
		if derr == nil {
			ok = 1
		}
		s.db.Exec(`INSERT OR REPLACE INTO backup_deliveries (snapshot_id, destination_id, object_name, ok, error, size, sha256, at) VALUES (?,?,?,?,?,?,?,?)`, //nolint:errcheck
			id, d.ID, obj, ok, msg, len(data), sum, sqltime.Format(time.Now()))
		if derr == nil && d.Retention > 0 {
			s.pruneDestination(d, drvFor(d))
		}
	}
}

func drvFor(d Destination) Driver {
	drv, _ := NewDriver(d)
	return drv
}

func (s *Scheduler) deliverOne(d Destination, id, obj, sum string, data []byte) error {
	drv, err := NewDriver(d)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := drv.Put(ctx, obj, data); err != nil {
		return fmt.Errorf("écriture : %w", err)
	}
	got, err := drv.Get(ctx, obj)
	if err != nil {
		return fmt.Errorf("relecture : %w", err)
	}
	if sha256Hex(got) != sum {
		return errors.New("la copie relue diffère du snapshot")
	}
	return nil
}

// pruneDestination supprime les copies les plus anciennes au-delà de la rétention de la destination.
func (s *Scheduler) pruneDestination(d Destination, drv Driver) {
	if drv == nil {
		return
	}
	rows, err := s.db.Query(`SELECT snapshot_id, object_name FROM backup_deliveries WHERE destination_id=? AND ok=1 ORDER BY at DESC LIMIT -1 OFFSET ?`, d.ID, d.Retention)
	if err != nil {
		return
	}
	type old struct{ id, obj string }
	var olds []old
	for rows.Next() {
		var o old
		if rows.Scan(&o.id, &o.obj) == nil {
			olds = append(olds, o)
		}
	}
	rows.Close()
	for _, o := range olds {
		if err := drv.Delete(context.Background(), o.obj); err != nil {
			s.log.Warn("backup: purge distante échouée", "destination", d.Name, "object", o.obj, "err", err)
			continue
		}
		s.db.Exec(`DELETE FROM backup_deliveries WHERE snapshot_id=? AND destination_id=?`, o.id, d.ID) //nolint:errcheck
	}
}

// ── État et sauvegardes manquées ──────────────────────────────────────────────

// DestStatus résume l'état d'une destination.
type DestStatus struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Enabled   bool       `json:"enabled"`
	LastOKAt  *time.Time `json:"last_ok_at,omitempty"`
	LastAt    *time.Time `json:"last_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Copies    int        `json:"copies"`
}

// Status résume la santé des sauvegardes.
type Status struct {
	KeySet         bool         `json:"key_set"` // GPX_BACKUP_KEY définie : snapshots avec section secrets
	LastSnapshotAt *time.Time   `json:"last_snapshot_at,omitempty"`
	LastVerifiedAt *time.Time   `json:"last_verified_at,omitempty"`
	Stale          []string     `json:"stale"` // planifications dont une exécution a été manquée
	Destinations   []DestStatus `json:"destinations"`
	Running        *RunInfo     `json:"running,omitempty"`  // sauvegarde ou copie externe en cours
	LastRun        *LastRun     `json:"last_run,omitempty"` // résultat de la dernière sauvegarde terminée
}

func parseTS(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := sqltime.Parse(s)
	if err != nil {
		return nil
	}
	return &t
}

// Status calcule l'état courant.
func (s *Scheduler) Status() Status {
	st := Status{Stale: []string{}, Destinations: []DestStatus{}}
	_, st.KeySet = importer.BackupKey()
	st.Running = s.Running()
	st.LastRun = s.LastRun()
	var last, ver sql.NullString
	s.db.QueryRow(`SELECT MAX(created_at), MAX(verified_at) FROM backup_snapshots`).Scan(&last, &ver) //nolint:errcheck
	st.LastSnapshotAt, st.LastVerifiedAt = parseTS(last.String), parseTS(ver.String)
	for _, sc := range s.staleSchedules() {
		st.Stale = append(st.Stale, sc.Name)
	}
	ds, _ := s.loadDestinations(false)
	for _, d := range ds {
		dst := DestStatus{ID: d.ID, Name: d.Name, Type: d.Type, Enabled: d.Enabled}
		var okAt, at sql.NullString
		s.db.QueryRow(`SELECT MAX(at) FROM backup_deliveries WHERE destination_id=? AND ok=1`, d.ID).Scan(&okAt)                                 //nolint:errcheck
		s.db.QueryRow(`SELECT at, error FROM backup_deliveries WHERE destination_id=? ORDER BY at DESC LIMIT 1`, d.ID).Scan(&at, &dst.LastError) //nolint:errcheck
		s.db.QueryRow(`SELECT COUNT(*) FROM backup_deliveries WHERE destination_id=? AND ok=1`, d.ID).Scan(&dst.Copies)                          //nolint:errcheck
		dst.LastOKAt, dst.LastAt = parseTS(okAt.String), parseTS(at.String)
		st.Destinations = append(st.Destinations, dst)
	}
	return st
}

// staleSchedules renvoie les planifications actives dont la dernière exécution attendue est passée
// depuis plus de staleGrace sans nouveau snapshot.
func (s *Scheduler) staleSchedules() []Schedule {
	var out []Schedule
	for _, sch := range s.GetConfig().Schedules {
		if !sch.Enabled {
			continue
		}
		expr, err := sch.CronExpr()
		if err != nil || expr == "" {
			continue
		}
		var last sql.NullString
		s.db.QueryRow(`SELECT MAX(created_at) FROM backup_snapshots WHERE schedule_id=?`, sch.ID).Scan(&last) //nolint:errcheck
		lt := parseTS(last.String)
		if lt == nil {
			continue
		}
		next, err := nextCron(expr, *lt)
		if err == nil && time.Since(next) > staleGrace {
			out = append(out, sch)
		}
	}
	return out
}

// checkStale alerte une fois par exécution manquée.
func (s *Scheduler) checkStale() {
	if s.staleNotified == nil {
		s.staleNotified = map[string]bool{}
	}
	for _, sch := range s.staleSchedules() {
		var last sql.NullString
		s.db.QueryRow(`SELECT MAX(created_at) FROM backup_snapshots WHERE schedule_id=?`, sch.ID).Scan(&last) //nolint:errcheck
		key := sch.ID + "|" + last.String
		if s.staleNotified[key] {
			continue
		}
		s.staleNotified[key] = true
		s.alert("critical", fmt.Sprintf("Sauvegarde « %s » manquée", sch.Name),
			map[string]any{"schedule": sch.Name, "last_snapshot": last.String})
	}
}

func (s *Scheduler) staleLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkStale()
		}
	}
}

// Deliveries renvoie, par snapshot, les copies externes connues.
func (s *Scheduler) Deliveries() map[string][]map[string]any {
	out := map[string][]map[string]any{}
	rows, err := s.db.Query(`SELECT v.snapshot_id, d.name, v.ok, v.error, v.at FROM backup_deliveries v JOIN backup_destinations d ON d.id=v.destination_id ORDER BY v.at`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var sid, name, msg, at string
		var ok int
		if rows.Scan(&sid, &name, &ok, &msg, &at) == nil {
			out[sid] = append(out[sid], map[string]any{"destination": name, "ok": ok == 1, "error": msg, "at": at})
		}
	}
	return out
}
