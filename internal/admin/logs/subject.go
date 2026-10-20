// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"database/sql"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// SubjectExportMaxLogs borne les lignes de log d'un export : au-delà, LogsTruncated est vrai.
const SubjectExportMaxLogs = 100000

// Les structures de l'export d'accès (RGPD Art. 15) et de portabilité (Art. 20). Les dates sont
// celles de la base, en UTC.
type (
	SubjectBan struct {
		ID        string `json:"id"`
		Domain    string `json:"domain,omitempty"`
		Reason    string `json:"reason,omitempty"`
		Source    string `json:"source"`
		ExpiresAt string `json:"expires_at,omitempty"`
		CreatedAt string `json:"created_at"`
	}
	SubjectBanEvent struct {
		Domain    string `json:"domain,omitempty"`
		Action    string `json:"action"`
		Reason    string `json:"reason,omitempty"`
		Source    string `json:"source"`
		CreatedAt string `json:"created_at"`
	}
	SubjectGeo struct {
		CountryCode string  `json:"country_code"`
		Country     string  `json:"country"`
		City        string  `json:"city,omitempty"`
		Region      string  `json:"region,omitempty"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		CachedAt    string  `json:"cached_at"`
	}
	SubjectAudit struct {
		ID        int64  `json:"id"`
		Actor     string `json:"actor"`
		UserID    string `json:"user_id,omitempty"`
		IP        string `json:"ip,omitempty"`
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		Detail    string `json:"detail,omitempty"`
		CreatedAt string `json:"created_at"`
	}
	SubjectAccount struct {
		ID        string   `json:"id"`
		Email     string   `json:"email"`
		Role      string   `json:"role"`
		Teams     []string `json:"teams,omitempty"`
		CreatedAt string   `json:"created_at"`
	}
)

// IPExport regroupe ce que l'Admin garde d'une adresse IP. Le fichier d'access log des passerelles
// n'en fait pas partie : il reste sur leur disque.
type IPExport struct {
	IP            string            `json:"ip"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Logs          []Entry           `json:"logs"`
	LogsTruncated bool              `json:"logs_truncated,omitempty"`
	Bans          []SubjectBan      `json:"bans"`
	BanHistory    []SubjectBanEvent `json:"ban_history"`
	GeoIP         *SubjectGeo       `json:"geoip,omitempty"`
	Audit         []SubjectAudit    `json:"audit"`
}

// UserExport regroupe ce que l'Admin garde d'un compte : profil (sans mot de passe), logs attribués
// et actions enregistrées au journal d'audit.
type UserExport struct {
	UserID        string          `json:"user_id"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Account       *SubjectAccount `json:"account,omitempty"`
	Logs          []Entry         `json:"logs"`
	LogsTruncated bool            `json:"logs_truncated,omitempty"`
	Audit         []SubjectAudit  `json:"audit"`
}

const exportEntryColumns = `id, ts, level, component, COALESCE(node_name,''), COALESCE(node_id,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(referrer,''), COALESCE(user_id,''), COALESCE(request_id,''), COALESCE(waf_matches,''), COALESCE(threat_signal,''), COALESCE(tls_ja3,''), COALESCE(tls_ja4,''), ip_truncated`

func (s *Store) subjectLogs(where string, args []any) ([]Entry, bool, error) {
	rows, err := s.db.Query(`SELECT `+exportEntryColumns+` FROM logs WHERE `+where+` ORDER BY id DESC LIMIT ?`,
		append(args, SubjectExportMaxLogs+1)...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var ts, waf string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.NodeID, &e.Domain, &e.Method, &e.Path,
			&e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message, &e.Referrer, &e.UserID, &e.RequestID, &waf,
			&e.ThreatSignal, &e.TLSJA3, &e.TLSJA4, &e.IPTruncated); err != nil {
			return nil, false, err
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		e.WAFMatches = decodeWAFMatches(waf)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(out) > SubjectExportMaxLogs
	if truncated {
		out = out[:SubjectExportMaxLogs]
	}
	return out, truncated, nil
}

func (s *Store) subjectAudit(where string, args ...any) ([]SubjectAudit, error) {
	rows, err := s.db.Query(`SELECT id, actor, user_id, ip, action, resource, COALESCE(detail,''), created_at
		FROM audit_log WHERE `+where+` ORDER BY id DESC LIMIT 10000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubjectAudit{}
	for rows.Next() {
		var a SubjectAudit
		if err := rows.Scan(&a.ID, &a.Actor, &a.UserID, &a.IP, &a.Action, &a.Resource, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExportIP rassemble les données d'une IP (droit d'accès, Art. 15). Les entrées pseudonymisées sont
// retrouvées par leur empreinte ; leur IP est celle qu'on demande, jamais déchiffrée.
func (s *Store) ExportIP(ip string) (IPExport, error) {
	canon := ipcrypt.CanonicalIP(ip)
	out := IPExport{IP: canon, GeneratedAt: time.Now().UTC(), Bans: []SubjectBan{}, BanHistory: []SubjectBanEvent{}}

	s.pseudoMu.RLock()
	key := s.gdprKey
	s.pseudoMu.RUnlock()
	where, args := `ip IN (?, ?)`, []any{ip, canon}
	if key != nil {
		where += ` OR ip_hmac = ?`
		args = append(args, ipcrypt.IPIndex(key, canon))
	}
	var err error
	if out.Logs, out.LogsTruncated, err = s.subjectLogs(where, args); err != nil {
		return out, err
	}
	for i := range out.Logs {
		if out.Logs[i].IP == PseudonymizedIP {
			out.Logs[i].IP = canon
		}
	}

	rows, err := s.db.Query(`SELECT id, domain, reason, source, COALESCE(expires_at,''), COALESCE(created_at,'') FROM security_bans WHERE ip IN (?, ?)`, ip, canon)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var b SubjectBan
		if err := rows.Scan(&b.ID, &b.Domain, &b.Reason, &b.Source, &b.ExpiresAt, &b.CreatedAt); err != nil {
			rows.Close()
			return out, err
		}
		out.Bans = append(out.Bans, b)
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT domain, action, reason, source, COALESCE(created_at,'') FROM security_ban_history WHERE ip IN (?, ?) ORDER BY id`, ip, canon)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var b SubjectBanEvent
		if err := rows.Scan(&b.Domain, &b.Action, &b.Reason, &b.Source, &b.CreatedAt); err != nil {
			rows.Close()
			return out, err
		}
		out.BanHistory = append(out.BanHistory, b)
	}
	rows.Close()

	var g SubjectGeo
	err = s.db.QueryRow(`SELECT country_code, country_name, city, region, COALESCE(lat,0), COALESCE(lon,0), COALESCE(cached_at,'') FROM geoip_cache WHERE ip IN (?, ?) LIMIT 1`, ip, canon).
		Scan(&g.CountryCode, &g.Country, &g.City, &g.Region, &g.Lat, &g.Lon, &g.CachedAt)
	switch {
	case err == nil:
		out.GeoIP = &g
	case err != sql.ErrNoRows:
		return out, err
	}

	out.Audit, err = s.subjectAudit(`ip IN (?, ?)`, ip, canon)
	return out, err
}

// ExportUser rassemble les données d'un compte (droit d'accès, Art. 15, et portabilité, Art. 20).
func (s *Store) ExportUser(userID string) (UserExport, error) {
	out := UserExport{UserID: userID, GeneratedAt: time.Now().UTC()}
	var err error
	if out.Logs, out.LogsTruncated, err = s.subjectLogs(`user_id = ?`, []any{userID}); err != nil {
		return out, err
	}
	var acc SubjectAccount
	err = s.db.QueryRow(`SELECT id, email, role, COALESCE(created_at,'') FROM users WHERE id = ?`, userID).
		Scan(&acc.ID, &acc.Email, &acc.Role, &acc.CreatedAt)
	switch {
	case err == nil:
		rows, err := s.db.Query(`SELECT t.name FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ? ORDER BY t.name`, userID)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return out, err
			}
			acc.Teams = append(acc.Teams, n)
		}
		rows.Close()
		out.Account = &acc
	case err != sql.ErrNoRows:
		return out, err
	}
	out.Audit, err = s.subjectAudit(`user_id = ? OR actor = ?`, userID, userID)
	return out, err
}
