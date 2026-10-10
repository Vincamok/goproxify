// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type dryRunCheck struct {
	Check   string   `json:"check"`
	Status  string   `json:"status"` // "ok" | "warning" | "error" | "skip"
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

type dryRunResponse struct {
	OK      bool            `json:"ok"`
	Summary map[string]any  `json:"summary,omitempty"`
	Checks  []dryRunCheck   `json:"checks"`
	Probes  []pathTestStep  `json:"probes,omitempty"`
	Route   json.RawMessage `json:"route,omitempty"`
}

// dryRun valide une config sans rien écrire : mêmes règles que le dry-run de la
// passerelle (structure, conflits host/alias/port avec les proxies en production),
// plus une sonde optionnelle des backends.
func (h *ProxiesHandler) dryRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string          `json:"id"`
		Config  json.RawMessage `json:"config"`
		Enabled *bool           `json:"enabled"`
		Probe   bool            `json:"probe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	body.Config, _ = h.restoreSecrets(r.Context(), body.ID, body.Config)
	var route router.Route
	if err := json.Unmarshal(body.Config, &route); err != nil {
		jsonOK(w, dryRunResponse{Checks: []dryRunCheck{{Check: "syntax", Status: "error", Message: "Config illisible : " + err.Error()}}})
		return
	}
	id := body.ID
	if id == "" {
		id = "dry-run"
	}
	route.ID = id
	userID := auth.UserIDFromContext(r.Context())
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope_domain")
		return
	}

	resp := dryRunResponse{Checks: []dryRunCheck{{Check: "syntax", Status: "ok", Message: "Config lisible et conforme au schéma."}}}
	backends := make([]string, 0, len(route.Backends))
	for _, b := range route.Backends {
		backends = append(backends, b.URL)
	}
	resp.Summary = map[string]any{
		"type": route.Type, "host": route.Host, "aliases": route.Aliases,
		"backends": backends, "tls_enabled": route.TLSEnabled, "listen_port": route.ListenPort,
	}

	peers, peersErr := h.productionPeers(r, id)
	env := &proxystore.Envelope{SchemaVersion: 1, ID: id, Host: route.Host, Config: body.Config, Status: proxystore.StatusPending}
	result := proxypipeline.RunDryRun(env, peers, proxypipeline.DryRunOptions{})

	var structure, conflicts []string
	for _, e := range result.Errors {
		if strings.Contains(e, "conflit") || strings.Contains(e, "déjà") || strings.Contains(e, "entre en conflit") {
			conflicts = append(conflicts, e)
		} else {
			structure = append(structure, e)
		}
	}
	resp.Checks = append(resp.Checks, checkFromErrors("structure", "Type, host, backends et URLs valides.", structure))
	switch {
	case peersErr != nil:
		resp.Checks = append(resp.Checks, dryRunCheck{Check: "conflicts", Status: "warning", Message: "Conflits non vérifiés : aucune passerelle n'a répondu.", Details: []string{peersErr.Error()}})
		if len(conflicts) > 0 {
			resp.Checks[len(resp.Checks)-1] = checkFromErrors("conflicts", "", conflicts)
		}
	default:
		resp.Checks = append(resp.Checks, checkFromErrors("conflicts", "Aucun conflit host, alias ou port avec les proxies en production.", conflicts))
	}
	if body.Enabled != nil && !*body.Enabled {
		resp.Checks = append(resp.Checks, dryRunCheck{Check: "enabled", Status: "warning", Message: "Le proxy est désactivé : il ne sera pas routé."})
	}

	if body.Probe {
		resp.Probes = runPathTest(r.Context(), route.Host, strings.ToLower(string(route.Type)), body.Enabled == nil || *body.Enabled, route.TLSEnabled, route.TLSPassthrough, backends)
	} else {
		resp.Checks = append(resp.Checks, dryRunCheck{Check: "probes", Status: "skip", Message: "Sonde des backends non demandée."})
	}

	resp.OK = true
	for _, c := range resp.Checks {
		if c.Status == "error" {
			resp.OK = false
		}
	}
	if raw, err := json.Marshal(route); err == nil {
		resp.Route = raw
	}
	jsonOK(w, resp)
}

func checkFromErrors(name, okMsg string, errs []string) dryRunCheck {
	if len(errs) == 0 {
		return dryRunCheck{Check: name, Status: "ok", Message: okMsg}
	}
	return dryRunCheck{Check: name, Status: "error", Message: errs[0], Details: errs}
}

func (h *ProxiesHandler) productionPeers(r *http.Request, excludeID string) ([]*proxystore.Envelope, error) {
	targets, err := edgeproxy.ListTargets(r.Context(), h.DB)
	if err != nil {
		return nil, err
	}
	client := edgeproxy.NewClient()
	var last error = errNoEdge
	for _, t := range targets {
		ctx := r.Context()
		res, err := client.List(ctx, t)
		if err != nil {
			last = err
			continue
		}
		peers := make([]*proxystore.Envelope, 0, len(res.Production))
		for _, e := range res.Production {
			if e.ID != excludeID {
				peers = append(peers, e)
			}
		}
		return peers, nil
	}
	return nil, last
}

