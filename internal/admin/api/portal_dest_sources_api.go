// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/destsync"
	"github.com/vincamok/goproxify/internal/sqltime"
)

const (
	destSourcesPath    = "/api/v1/portal/dest-sources"
	destCandidatesPath = "/api/v1/portal/dest-candidates"
)

type destSourceBody struct {
	EdgeName    string         `json:"edge_name"`
	Edge        string         `json:"edge"`
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Config      map[string]any `json:"config"`
	IntervalS   int            `json:"interval_s"`
	Enabled     *bool          `json:"enabled"`
	ExtraTags   []string       `json:"extra_tags"`
	AutoPublish *bool          `json:"auto_publish"`
	// SourceID (essai seulement) : source dont on reprend les secrets quand le formulaire les laisse masqués.
	SourceID string `json:"source_id"`
}

func (b destSourceBody) scope() string { return strings.TrimSpace(firstNonEmpty(b.EdgeName, b.Edge)) }

// handleDestSources route /api/v1/portal/dest-sources[/...].
func (h *PortalHandler) handleDestSources(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, destSourcesPath), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "types" && r.Method == http.MethodGet:
		jsonOK(w, map[string]any{"types": destSourceManifests()})
	case rest == "test" && r.Method == http.MethodPost:
		h.testDestSource(w, r)
	case rest == "" && r.Method == http.MethodGet:
		h.listDestSourcesAPI(w, r)
	case rest == "" && r.Method == http.MethodPost:
		h.createDestSource(w, r)
	case len(parts) == 1 && r.Method == http.MethodGet:
		h.getDestSource(w, r, parts[0])
	case len(parts) == 1 && r.Method == http.MethodPut:
		h.updateDestSource(w, r, parts[0])
	case len(parts) == 1 && r.Method == http.MethodDelete:
		h.deleteDestSource(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "sync" && r.Method == http.MethodPost:
		h.syncDestSource(w, r, parts[0])
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PortalHandler) listDestSourcesAPI(w http.ResponseWriter, r *http.Request) {
	scope := h.scope(portalEdgeParam(r))
	list, err := listDestSources(h.DB, scope)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	counts := map[string]map[string]int{}
	if rows, err := h.DB.Query(`SELECT source_id, state, COUNT(*) FROM portal_dest_candidates GROUP BY source_id, state`); err == nil {
		for rows.Next() {
			var id, state string
			var n int
			if rows.Scan(&id, &state, &n) == nil {
				if counts[id] == nil {
					counts[id] = map[string]int{}
				}
				counts[id][state] = n
			}
		}
		rows.Close()
	}
	for i := range list {
		list[i].Candidates = counts[list[i].ID]
		list[i] = list[i].masked()
	}
	jsonOK(w, map[string]any{"sources": list})
}

func (h *PortalHandler) getDestSource(w http.ResponseWriter, r *http.Request, id string) {
	d, err := loadDestSource(h.DB, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, d.masked())
}

func (h *PortalHandler) createDestSource(w http.ResponseWriter, r *http.Request) {
	var b destSourceBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	scope := h.scope(b.scope())
	b.Name, b.Type = strings.TrimSpace(b.Name), strings.TrimSpace(strings.ToLower(b.Type))
	if scope == "" || b.Name == "" || b.Type == "" {
		http.Error(w, "edge_name, name et type requis", http.StatusBadRequest)
		return
	}
	if b.Config == nil {
		b.Config = map[string]any{}
	}
	if err := validateDestSourceConfig(b.Type, b.Config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var dup int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM portal_dest_sources WHERE edge_name=? AND LOWER(name)=LOWER(?)`, scope, b.Name).Scan(&dup)
	if dup > 0 {
		http.Error(w, "une source de ce nom existe déjà sur cette passerelle", http.StatusConflict)
		return
	}
	id := uuid.New().String()
	now := sqltime.Format(time.Now().UTC())
	extra, _ := json.Marshal(normalizeTags(b.ExtraTags))
	enabled, auto := 1, 0
	if b.Enabled != nil && !*b.Enabled {
		enabled = 0
	}
	if b.AutoPublish != nil && *b.AutoPublish {
		auto = 1
	}
	if _, err := h.DB.Exec(`INSERT INTO portal_dest_sources (id, edge_name, type, name, config_enc, interval_s, enabled, extra_tags_json, auto_publish, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, id, scope, b.Type, b.Name, sealDestConfig(b.Config), b.IntervalS, enabled, string(extra), auto, now, now); err != nil {
		h.Log.Error("portal dest source create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create", "portal_dest_source", id)
	h.pushScope(r.Context(), scope)
	d, _ := loadDestSource(h.DB, id)
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, d.masked())
}

func (h *PortalHandler) updateDestSource(w http.ResponseWriter, r *http.Request, id string) {
	cur, err := loadDestSource(h.DB, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	var b destSourceBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	// Le type et la portée ne changent pas : les secrets d'un autre fournisseur n'auraient aucun sens, et les candidates
	// et destinations publiées sont rattachées à la portée de la source.
	if t := strings.TrimSpace(strings.ToLower(b.Type)); t != "" && t != cur.Type {
		http.Error(w, "le type d'une source ne se modifie pas : en créer une autre", http.StatusBadRequest)
		return
	}
	if s := h.scope(b.scope()); s != "" && s != cur.EdgeName {
		http.Error(w, "la passerelle d'une source ne se modifie pas : en créer une autre", http.StatusBadRequest)
		return
	}
	cfg := cur.Config
	if b.Config != nil {
		man, _ := destsync.ManifestOf(cur.Type)
		cfg = man.KeepSecrets(cur.Config, b.Config)
	}
	if err := validateDestSourceConfig(cur.Type, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := firstNonEmpty(b.Name, cur.Name)
	var dup int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM portal_dest_sources WHERE edge_name=? AND LOWER(name)=LOWER(?) AND id<>?`, cur.EdgeName, name, id).Scan(&dup)
	if dup > 0 {
		http.Error(w, "une source de ce nom existe déjà sur cette passerelle", http.StatusConflict)
		return
	}
	enabled, auto := cur.Enabled, cur.AutoPublish
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	if b.AutoPublish != nil {
		auto = *b.AutoPublish
	}
	extra := cur.ExtraTags
	if b.ExtraTags != nil {
		extra = normalizeTags(b.ExtraTags)
	}
	interval := cur.IntervalS
	if b.IntervalS != 0 {
		interval = b.IntervalS
	}
	rawExtra, _ := json.Marshal(extra)
	if _, err := h.DB.Exec(`UPDATE portal_dest_sources SET name=?, config_enc=?, interval_s=?, enabled=?, extra_tags_json=?, auto_publish=?, updated_at=? WHERE id=?`,
		name, sealDestConfig(cfg), interval, boolInt(enabled), string(rawExtra), boolInt(auto), sqltime.Format(time.Now().UTC()), id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal_dest_source", id)
	h.pushScope(r.Context(), cur.EdgeName)
	d, _ := loadDestSource(h.DB, id)
	jsonOK(w, d.masked())
}

func (h *PortalHandler) deleteDestSource(w http.ResponseWriter, r *http.Request, id string) {
	cur, err := loadDestSource(h.DB, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	// Les destinations déjà publiées restent : ce sont des destinations ordinaires, que l'opérateur gère comme les autres.
	_, _ = h.DB.Exec(`DELETE FROM portal_dest_candidates WHERE source_id=?`, id)
	if _, err := h.DB.Exec(`DELETE FROM portal_dest_sources WHERE id=?`, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_dest_source", id)
	h.pushScope(r.Context(), cur.EdgeName)
	w.WriteHeader(http.StatusNoContent)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// scopeTargets retourne les passerelles qui peuvent exécuter les sources d'une portée : elle-même, ou les membres de son groupe.
func (h *PortalHandler) scopeTargets(ctx context.Context, scope string) []edgeproxy.Target {
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return nil
	}
	want := map[string]bool{scope: true}
	if group, ok := strings.CutPrefix(scope, groupScopePrefix); ok && h.Groups != nil {
		want = map[string]bool{}
		for _, n := range memberNames(h.Groups, group) {
			want[n] = true
		}
	}
	var out []edgeproxy.Target
	for _, t := range targets {
		if want[t.NodeName] {
			out = append(out, t)
		}
	}
	return out
}

// testDestSource fait lire la source une fois par la passerelle, avec la configuration du formulaire.
func (h *PortalHandler) testDestSource(w http.ResponseWriter, r *http.Request) {
	var b destSourceBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	scope := h.scope(b.scope())
	b.Type = strings.TrimSpace(strings.ToLower(b.Type))
	if b.Config == nil {
		b.Config = map[string]any{}
	}
	if b.SourceID != "" {
		prev, err := loadDestSource(h.DB, b.SourceID)
		if err != nil {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		if scope != "" && prev.EdgeName != scope {
			http.Error(w, "source d'une autre passerelle", http.StatusBadRequest)
			return
		}
		scope = prev.EdgeName
		if b.Type == "" || b.Type == prev.Type {
			b.Type = prev.Type
			if man, ok := destsync.ManifestOf(prev.Type); ok {
				b.Config = man.KeepSecrets(prev.Config, b.Config)
			}
		}
	}
	if scope == "" || b.Type == "" {
		http.Error(w, "edge et type requis", http.StatusBadRequest)
		return
	}
	if err := validateDestSourceConfig(b.Type, b.Config); err != nil {
		jsonOK(w, edgeproxy.DestSourceTestResult{Error: err.Error()})
		return
	}
	targets := h.scopeTargets(r.Context(), scope)
	if len(targets) == 0 {
		jsonOK(w, edgeproxy.DestSourceTestResult{Error: "aucune passerelle joignable pour exécuter l'essai"})
		return
	}
	client := edgeproxy.NewClientTimeout(150 * time.Second)
	var lastErr error
	for _, t := range targets {
		res, err := client.TestDestSource(r.Context(), t, b.Type, b.Config)
		if err == nil {
			jsonOK(w, res)
			return
		}
		lastErr = err
	}
	jsonOK(w, edgeproxy.DestSourceTestResult{Error: "passerelle injoignable : " + lastErr.Error()})
}

// syncDestSource demande un passage immédiat à la passerelle qui exécute la source (le membre actif d'un groupe).
func (h *PortalHandler) syncDestSource(w http.ResponseWriter, r *http.Request, id string) {
	src, err := loadDestSource(h.DB, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	client := edgeproxy.NewClient()
	for _, t := range h.scopeTargets(r.Context(), src.EdgeName) {
		err := client.SyncDestSource(r.Context(), t, id)
		if err == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var he *edgeproxy.HTTPError
		if errors.As(err, &he) && he.Status == http.StatusNotFound {
			continue // ce membre n'exécute pas la source
		}
	}
	http.Error(w, "la source ne tourne sur aucune passerelle joignable (source désactivée, portail éteint ou passerelle hors ligne)", http.StatusConflict)
}

// --- candidates ------------------------------------------------------------------------------------------------------

// handleDestCandidates route /api/v1/portal/dest-candidates[/...].
func (h *PortalHandler) handleDestCandidates(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, destCandidatesPath), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.listDestCandidates(w, r)
	case rest == "publish" && r.Method == http.MethodPost:
		h.publishManyCandidates(w, r)
	case len(parts) == 2 && parts[1] == "publish" && r.Method == http.MethodPost:
		h.publishOneCandidate(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "ignore" && r.Method == http.MethodPost:
		h.moveCandidate(w, r, parts[0], CandNew, CandIgnored)
	case len(parts) == 2 && parts[1] == "restore" && r.Method == http.MethodPost:
		h.moveCandidate(w, r, parts[0], CandIgnored, CandNew)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		h.deleteCandidate(w, r, parts[0])
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PortalHandler) listDestCandidates(w http.ResponseWriter, r *http.Request) {
	scope := h.scope(portalEdgeParam(r))
	q := `SELECT c.id, c.source_id, c.edge_name, c.external_id, c.name, c.host, c.port, c.tags_json, c.running, c.detail_json, c.state, c.dest_id, c.first_seen, c.last_seen,
		s.name, s.type FROM portal_dest_candidates c LEFT JOIN portal_dest_sources s ON s.id=c.source_id WHERE 1=1`
	var args []any
	if scope != "" {
		q += ` AND c.edge_name=?`
		args = append(args, scope)
	}
	if st := strings.TrimSpace(r.URL.Query().Get("state")); st != "" {
		q += ` AND c.state=?`
		args = append(args, st)
	}
	if src := strings.TrimSpace(r.URL.Query().Get("source")); src != "" {
		q += ` AND c.source_id=?`
		args = append(args, src)
	}
	rows, err := h.DB.Query(q+` ORDER BY c.state='new' DESC, c.name`, args...)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []DestCandidate{}
	for rows.Next() {
		var c DestCandidate
		var tags, detail string
		var run int
		var sn, st sql.NullString
		if err := rows.Scan(&c.ID, &c.SourceID, &c.EdgeName, &c.ExternalID, &c.Name, &c.Host, &c.Port, &tags, &run, &detail, &c.State, &c.DestID, &c.FirstSeen, &c.LastSeen, &sn, &st); err != nil {
			continue
		}
		c.Running = run != 0
		c.SourceName, c.SourceType = sn.String, st.String
		_ = json.Unmarshal([]byte(tags), &c.Tags)
		c.Tags = normalizeTags(c.Tags)
		_ = json.Unmarshal([]byte(detail), &c.Detail)
		out = append(out, c)
	}
	jsonOK(w, map[string]any{"candidates": out})
}

func loadCandidate(db dbtx, id string) (DestCandidate, error) {
	return scanDestCandidate(db.QueryRow(`SELECT `+destCandCols+` FROM portal_dest_candidates WHERE id=?`, id))
}

func (h *PortalHandler) publishOneCandidate(w http.ResponseWriter, r *http.Request, id string) {
	var ov PublishOverrides
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&ov) // corps facultatif
	}
	destID, status, err := h.publishByID(r, id, ov)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	h.pushScope(r.Context(), h.candidateScope(id))
	jsonOK(w, map[string]any{"published": true, "destination_id": destID})
}

func (h *PortalHandler) candidateScope(id string) string {
	var s string
	_ = h.DB.QueryRow(`SELECT edge_name FROM portal_dest_candidates WHERE id=?`, id).Scan(&s)
	return s
}

// publishByID publie une candidate : 404 si elle n'existe pas, 409 si elle n'est pas dans un état publiable, 400 sinon.
func (h *PortalHandler) publishByID(r *http.Request, id string, ov PublishOverrides) (string, int, error) {
	c, err := loadCandidate(h.DB, id)
	if err == sql.ErrNoRows {
		return "", http.StatusNotFound, errors.New("candidate introuvable")
	}
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	if c.State != CandNew && c.State != CandIgnored {
		return "", http.StatusConflict, errors.New("cette machine est déjà publiée ou a disparu du fournisseur")
	}
	src, err := loadDestSource(h.DB, c.SourceID)
	if err != nil {
		return "", http.StatusConflict, errors.New("source introuvable")
	}
	destID, err := publishCandidate(h.DB, c, src, ov)
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "publish", "portal_dest_candidate", id)
	return destID, http.StatusOK, nil
}

func (h *PortalHandler) publishManyCandidates(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs  []string `json:"ids"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 {
		http.Error(w, "ids requis", http.StatusBadRequest)
		return
	}
	type skipped struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	published, skips := 0, []skipped{}
	scopes := map[string]bool{}
	for _, id := range body.IDs {
		scope := h.candidateScope(id)
		if _, _, err := h.publishByID(r, id, PublishOverrides{Tags: body.Tags}); err != nil {
			skips = append(skips, skipped{ID: id, Reason: err.Error()})
			continue
		}
		published++
		scopes[scope] = true
	}
	for scope := range scopes {
		h.pushScope(r.Context(), scope)
	}
	jsonOK(w, map[string]any{"published": published, "skipped": skips})
}

func (h *PortalHandler) moveCandidate(w http.ResponseWriter, r *http.Request, id, from, to string) {
	res, err := h.DB.Exec(`UPDATE portal_dest_candidates SET state=? WHERE id=? AND state=?`, to, id, from)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		if h.DB.QueryRow(`SELECT 1 FROM portal_dest_candidates WHERE id=?`, id).Scan(&one) == sql.ErrNoRows {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		http.Error(w, "état de la candidate incompatible avec cette action", http.StatusConflict)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), to, "portal_dest_candidate", id)
	w.WriteHeader(http.StatusNoContent)
}

// deleteCandidate retire une candidate de la file. Une machine publiée se retire en supprimant sa destination.
func (h *PortalHandler) deleteCandidate(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.Exec(`DELETE FROM portal_dest_candidates WHERE id=? AND state<>?`, id, CandPublished)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		if h.DB.QueryRow(`SELECT 1 FROM portal_dest_candidates WHERE id=?`, id).Scan(&one) == sql.ErrNoRows {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		http.Error(w, "machine publiée : supprimer sa destination", http.StatusConflict)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_dest_candidate", id)
	w.WriteHeader(http.StatusNoContent)
}
