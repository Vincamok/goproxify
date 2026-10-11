// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/automation"
)

// AutomationHandler expose les flux d'automatisation sous /api/v1/automation/ (règles, planifications et
// playbooks sont des flux qui ne diffèrent que par leur déclencheur).
type AutomationHandler struct {
	Svc *automation.Service
}

const automationPrefix = "/api/v1/automation/"

func (h *AutomationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, automationPrefix), "/"), "/")
	m := r.Method
	switch {
	case parts[0] == "flows":
		h.flows(w, r, parts[1:])
	case parts[0] == "runs":
		h.runs(w, r, parts[1:])
	case parts[0] == "simulate" && m == http.MethodPost:
		h.simulate(w, r)
	case parts[0] == "catalog" && m == http.MethodGet:
		jsonOK(w, h.Svc.Catalog())
	case parts[0] == "options" && len(parts) == 2 && m == http.MethodGet:
		opts, err := h.Svc.Options(r.Context(), parts[1])
		h.reply(w, r, opts, err)
	case parts[0] == "templates":
		h.templates(w, r, parts[1:])
	case parts[0] == "silences":
		h.silences(w, r, parts[1:])
	case parts[0] == "stats" && m == http.MethodGet:
		st, err := h.Svc.Stats(r.Context())
		h.reply(w, r, st, err)
	case parts[0] == "export" && m == http.MethodGet:
		data, err := h.Svc.Export(r.Context())
		if err != nil {
			h.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", `attachment; filename="automation.yaml"`)
		_, _ = w.Write(data)
	case parts[0] == "import" && m == http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
			return
		}
		sum, err := h.Svc.Import(r.Context(), raw, h.actor(r))
		h.reply(w, r, sum, err)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

// fail traduit une erreur du service : saisie invalide 400, introuvable 404, flux de modèle 409.
func (h *AutomationHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var verr *automation.ValidationError
	switch {
	case errors.As(err, &verr):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, automation.ErrNotFound):
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	case errors.Is(err, automation.ErrTemplateManaged):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
	}
}

func (h *AutomationHandler) reply(w http.ResponseWriter, r *http.Request, v any, err error) {
	if err != nil {
		h.fail(w, r, err)
		return
	}
	jsonOK(w, v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "JSON invalide : "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (h *AutomationHandler) actor(r *http.Request) string {
	ctx := r.Context()
	return h.Svc.ActorLabel(ctx, adminauth.UserIDFromContext(ctx), adminauth.ActorFromContext(ctx))
}

func (h *AutomationHandler) flows(w http.ResponseWriter, r *http.Request, p []string) {
	ctx := r.Context()
	m := r.Method
	id, sub := "", ""
	if len(p) > 0 {
		id = p[0]
	}
	if len(p) > 1 {
		sub = p[1]
	}
	switch {
	case id == "" && m == http.MethodGet:
		var kinds []automation.TriggerKind
		for _, k := range strings.Split(r.URL.Query().Get("trigger"), ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, automation.TriggerKind(k))
			}
		}
		list, err := h.Svc.List(ctx, kinds...)
		h.reply(w, r, list, err)
	case id == "" && m == http.MethodPost:
		var f automation.Flow
		if decode(w, r, &f) {
			out, err := h.Svc.Create(ctx, &f, h.actor(r))
			h.reply(w, r, out, err)
		}
	case sub == "" && m == http.MethodGet:
		f, err := h.Svc.Get(ctx, id)
		h.reply(w, r, f, err)
	case sub == "" && m == http.MethodPut:
		h.update(w, r, id)
	case sub == "" && m == http.MethodPatch:
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Enabled == nil {
			http.Error(w, "enabled requis", http.StatusBadRequest)
			return
		}
		f, err := h.Svc.SetEnabled(ctx, id, *body.Enabled)
		h.reply(w, r, f, err)
	case sub == "" && m == http.MethodDelete:
		if err := h.Svc.Delete(ctx, id); err != nil {
			h.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case sub == "run" && m == http.MethodPost:
		var body struct {
			Inputs map[string]any `json:"inputs"`
			DryRun bool           `json:"dry_run"`
		}
		if r.ContentLength != 0 && !decode(w, r, &body) {
			return
		}
		if body.DryRun {
			f, err := h.Svc.Get(ctx, id)
			if err != nil {
				h.fail(w, r, err)
				return
			}
			res, err := h.Svc.Simulate(ctx, f, body.Inputs)
			h.reply(w, r, res, err)
			return
		}
		res, err := h.Svc.RunNow(ctx, id, body.Inputs, h.actor(r))
		h.reply(w, r, res, err)
	case sub == "detach" && m == http.MethodPost:
		f, err := h.Svc.Detach(ctx, id, h.actor(r))
		h.reply(w, r, f, err)
	case sub == "versions" && len(p) == 2 && m == http.MethodGet:
		v, err := h.Svc.Versions(ctx, id)
		h.reply(w, r, v, err)
	case sub == "versions" && len(p) == 4 && p[3] == "restore" && m == http.MethodPost:
		v, err := strconv.Atoi(p[2])
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
			return
		}
		f, err := h.Svc.Restore(ctx, id, v, h.actor(r))
		h.reply(w, r, f, err)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

// update : un flux issu d'un modèle se modifie par ses paramètres (origin.params), les autres par leur
// définition complète.
func (h *AutomationHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	cur, err := h.Svc.Get(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var f automation.Flow
	if !decode(w, r, &f) {
		return
	}
	if cur.Origin.Kind == automation.OriginTemplate && f.Origin.Kind == automation.OriginTemplate {
		params := f.Origin.Params
		if params == nil {
			params = cur.Origin.Params
		}
		out, err := h.Svc.UpdateParams(ctx, id, automation.TemplateUpdate{Name: f.Name, Description: f.Description, Enabled: f.Enabled, Params: params}, h.actor(r))
		h.reply(w, r, out, err)
		return
	}
	out, err := h.Svc.Update(ctx, id, &f, h.actor(r))
	h.reply(w, r, out, err)
}

func (h *AutomationHandler) simulate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Flow   automation.Flow `json:"flow"`
		Inputs map[string]any  `json:"inputs"`
	}
	if decode(w, r, &body) {
		res, err := h.Svc.Simulate(r.Context(), &body.Flow, body.Inputs)
		h.reply(w, r, res, err)
	}
}

func (h *AutomationHandler) runs(w http.ResponseWriter, r *http.Request, p []string) {
	ctx := r.Context()
	if len(p) == 0 || p[0] == "" {
		if r.Method != http.MethodGet {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		q := r.URL.Query()
		f := automation.RunFilter{FlowID: q.Get("flow_id"), Source: q.Get("source")}
		for _, st := range strings.Split(q.Get("status"), ",") {
			if st = strings.TrimSpace(st); st != "" {
				f.Status = append(f.Status, automation.RunStatus(st))
			}
		}
		if n, err := strconv.Atoi(q.Get("limit")); err == nil {
			f.Limit = n
		}
		if s := q.Get("since"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				f.Since = t
			} else if d, err := time.ParseDuration(s); err == nil {
				f.Since = time.Now().Add(-d)
			}
		}
		list, err := h.Svc.Runs(ctx, f)
		h.reply(w, r, list, err)
		return
	}
	id := p[0]
	sub := ""
	if len(p) > 1 {
		sub = p[1]
	}
	switch {
	case sub == "" && r.Method == http.MethodGet:
		run, err := h.Svc.GetRun(ctx, id)
		h.reply(w, r, run, err)
	case (sub == "approve" || sub == "reject") && r.Method == http.MethodPost:
		err := h.Svc.Decide(ctx, id, sub == "approve", h.actor(r))
		h.reply(w, r, map[string]bool{"ok": true}, err)
	case sub == "cancel" && r.Method == http.MethodPost:
		err := h.Svc.Cancel(ctx, id, h.actor(r))
		h.reply(w, r, map[string]bool{"ok": true}, err)
	case sub == "replay" && r.Method == http.MethodPost:
		res, err := h.Svc.Replay(ctx, id, h.actor(r))
		h.reply(w, r, res, err)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *AutomationHandler) templates(w http.ResponseWriter, r *http.Request, p []string) {
	ctx := r.Context()
	switch {
	case (len(p) == 0 || p[0] == "") && r.Method == http.MethodGet:
		list, err := h.Svc.ListTemplates(ctx)
		h.reply(w, r, list, err)
	case len(p) == 2 && p[1] == "preview" && r.Method == http.MethodPost:
		var body struct {
			Params map[string]any `json:"params"`
			FlowID string         `json:"flow_id"`
		}
		if decode(w, r, &body) {
			f, err := h.Svc.Preview(ctx, p[0], body.Params, body.FlowID)
			h.reply(w, r, f, err)
		}
	case len(p) == 2 && p[1] == "install" && r.Method == http.MethodPost:
		body := automation.TemplateUpdate{Enabled: true}
		if r.ContentLength != 0 && !decode(w, r, &body) {
			return
		}
		f, err := h.Svc.Install(ctx, p[0], body, h.actor(r))
		h.reply(w, r, f, err)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *AutomationHandler) silences(w http.ResponseWriter, r *http.Request, p []string) {
	ctx := r.Context()
	switch {
	case (len(p) == 0 || p[0] == "") && r.Method == http.MethodGet:
		list, err := h.Svc.Silences(ctx)
		h.reply(w, r, list, err)
	case (len(p) == 0 || p[0] == "") && r.Method == http.MethodPost:
		var sl automation.Silence
		if decode(w, r, &sl) {
			out, err := h.Svc.CreateSilence(ctx, sl)
			h.reply(w, r, out, err)
		}
	case len(p) == 1 && r.Method == http.MethodDelete:
		if err := h.Svc.DeleteSilence(ctx, p[0]); err != nil {
			h.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}
