// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"sort"
	"strings"
)

// MinuteRow est le cumul d'une minute pour un domaine et un code de statut : les mêmes colonnes que logs_minute
// côté Admin. Il ne contient ni IP ni chemin, donc rien de personnel.
type MinuteRow struct {
	Minute       string // AAAA-MM-JJTHH:MM, UTC
	Domain       string
	Status       int
	Requests     int64
	Bytes        int64
	LatencyMsSum int64
	Bots         int64
	// Seq croît à chaque mise à jour de la ligne : c'est le curseur du flux vers l'Admin. Il ne dépend pas du
	// fichier de période, car une requête tardive met à jour un fichier ancien.
	Seq int64
}

const minuteLayout = "2006-01-02T15:04"

type minuteKey struct {
	minute, domain string
	status         int
}

// isBot reconnaît un robot comme l'agrégation de l'Admin le faisait sur le message d'accès : la mention « bot »
// dans l'agent utilisateur, le référent ou le chemin.
func isBot(e *Entry) bool {
	return strings.Contains(strings.ToLower(e.UserAgent), "bot") ||
		strings.Contains(strings.ToLower(e.Referrer), "bot") ||
		strings.Contains(strings.ToLower(e.Path), "bot")
}

// nextMinuteSeqs réserve n numéros de mise à jour consécutifs, croissants d'un appel à l'autre : l'heure en
// microsecondes, repoussée si elle recule ou si plusieurs lots tombent dans la même microseconde.
func (s *Store) nextMinuteSeqs(n int) int64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	base := max(s.opts.Now().UnixMicro(), s.minuteLast+1)
	s.minuteLast = base + int64(n) - 1
	return base
}

// scanMinuteMax relève, une fois à l'ouverture, le dernier numéro de mise à jour de chaque fichier : ReadMinutesAfter
// n'ouvre ensuite que les fichiers qui ont changé depuis la position demandée, aussi anciens soient-ils (une requête
// très longue met à jour le fichier de la semaine où elle a commencé). Le plus grand sert aussi de point de départ aux
// nouveaux numéros : une horloge qui aurait reculé pendant un redémarrage ne les ferait pas repasser sous ceux de l'Admin.
func (s *Store) scanMinuteMax() {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.fileMax = map[string]int64{}
	s.ipFileMax = map[string]int64{}
	s.ipPruned = map[string]bool{}
	for _, f := range s.files(KindAccess) {
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			continue
		}
		var last, lastIP int64
		if err := db.QueryRow(`SELECT COALESCE(MAX(updated_us), 0) FROM minute`).Scan(&last); err != nil {
			continue
		}
		_ = db.QueryRow(`SELECT COALESCE(MAX(updated_us), 0) FROM ip_errors`).Scan(&lastIP)
		s.fileMax[f.path] = last
		s.ipFileMax[f.path] = lastIP
		s.minuteLast = max(s.minuteLast, last, lastIP)
	}
}

// noteMinuteMax retient le dernier numéro attribué dans un fichier, une fois la transaction validée.
func (s *Store) noteMinuteMax(path string, seq int64) {
	s.seqMu.Lock()
	if s.fileMax != nil && seq > s.fileMax[path] {
		s.fileMax[path] = seq
	}
	s.seqMu.Unlock()
}

// upsertMinutes ajoute les accès du lot aux cumuls de leur minute, dans la transaction qui écrit les lignes :
// les cumuls ne peuvent pas s'écarter des lignes.
func upsertMinutes(tx *sql.Tx, s *Store, entries []Entry) (maxSeq int64, err error) {
	type sums struct{ req, bytes, lat, bots int64 }
	agg := map[minuteKey]*sums{}
	for i := range entries {
		e := &entries[i]
		if e.Status <= 0 {
			continue
		}
		k := minuteKey{e.Ts.UTC().Format(minuteLayout), e.Domain, e.Status}
		a := agg[k]
		if a == nil {
			a = &sums{}
			agg[k] = a
		}
		a.req++
		a.bytes += e.Bytes
		a.lat += e.LatencyMs
		if isBot(e) {
			a.bots++
		}
	}
	if len(agg) == 0 {
		return 0, nil
	}
	keys := make([]minuteKey, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].minute < keys[j].minute })
	seq := s.nextMinuteSeqs(len(keys))
	stmt, err := tx.Prepare(`INSERT INTO minute (minute, domain, status, requests, bytes, latency_ms_sum, bots, updated_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (minute, domain, status) DO UPDATE SET
			requests = requests + excluded.requests, bytes = bytes + excluded.bytes,
			latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum, bots = bots + excluded.bots,
			updated_us = excluded.updated_us`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for i, k := range keys {
		a := agg[k]
		if _, err := stmt.Exec(k.minute, k.domain, k.status, a.req, a.bytes, a.lat, a.bots, seq+int64(i)); err != nil {
			return 0, err
		}
	}
	return seq + int64(len(keys)) - 1, nil
}

// ReadMinutesAfter retourne jusqu'à limit cumuls mis à jour après after, dans l'ordre des mises à jour. Un
// consommateur qui a reçu jusqu'à la position p redemande avec after = p : il reçoit la dernière valeur de chaque
// minute modifiée depuis. after = 0 : tout.
func (s *Store) ReadMinutesAfter(after int64, limit int) ([]MinuteRow, error) {
	if limit <= 0 {
		return nil, nil
	}
	var all []MinuteRow
	for _, f := range s.files(KindAccess) {
		s.seqMu.Lock()
		changed := s.fileMax[f.path] > after
		s.seqMu.Unlock()
		if !changed {
			continue
		}
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			return nil, err
		}
		rows, err := db.Query(`SELECT minute, domain, status, requests, bytes, latency_ms_sum, bots, updated_us
			FROM minute WHERE updated_us > ? ORDER BY updated_us LIMIT ?`, after, limit)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r MinuteRow
			if err := rows.Scan(&r.Minute, &r.Domain, &r.Status, &r.Requests, &r.Bytes, &r.LatencyMsSum, &r.Bots, &r.Seq); err != nil {
				rows.Close()
				return nil, err
			}
			all = append(all, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	// Les limit plus petits de chaque fichier contiennent les limit plus petits de l'ensemble.
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}
