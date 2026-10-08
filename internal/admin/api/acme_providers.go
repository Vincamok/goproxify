// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/acme"
)

// ACMEProvidersHandler gère GET/POST /api/v1/acme/providers
// et GET/PUT/DELETE /api/v1/acme/providers/{id}.
type ACMEProvidersHandler struct {
	Store *acme.ProviderStore
	Log   *slog.Logger
}

func (h *ACMEProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/acme/providers")
	path = strings.TrimPrefix(path, "/")
	id := path

	switch {
	case id == "" && r.Method == http.MethodGet:
		h.list(w, r)
	case id == "" && r.Method == http.MethodPost:
		h.create(w, r)
	case id != "" && r.Method == http.MethodGet:
		h.get(w, r, id)
	case id != "" && r.Method == http.MethodPut:
		h.update(w, r, id)
	case id != "" && r.Method == http.MethodDelete:
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method_not_allowed")
	}
}

func (h *ACMEProvidersHandler) list(w http.ResponseWriter, _ *http.Request) {
	entries, err := h.Store.List()
	if err != nil {
		h.Log.Error("acme_providers: list", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []acme.ProviderEntry{}
	}
	for i := range entries {
		entries[i] = maskProviderEntry(entries[i])
	}
	jsonOK(w, entries)
}

func (h *ACMEProvidersHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	e, err := h.Store.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if e == nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, maskProviderEntry(*e))
}

func (h *ACMEProvidersHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	if body.Name == "" || body.Type == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_fields")
		return
	}
	man, ok := acme.DNSProviderManifest(body.Type)
	if !ok {
		http.Error(w, "fournisseur DNS inconnu : "+body.Type, http.StatusBadRequest)
		return
	}
	if err := man.Validate(paramsAny(body.Params)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := h.Store.Create(body.Name, body.Type, body.Params)
	if err != nil {
		h.Log.Error("acme_providers: create", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: créé", "id", id, "name", body.Name)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id}) //nolint:errcheck
}

func (h *ACMEProvidersHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	man, ok := acme.DNSProviderManifest(body.Type)
	if !ok {
		http.Error(w, "fournisseur DNS inconnu : "+body.Type, http.StatusBadRequest)
		return
	}
	old, err := h.Store.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if old == nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	params := paramsAny(body.Params)
	if old.Type == body.Type { // les secrets d'un autre type n'ont pas le même sens
		params = man.KeepSecrets(paramsAny(old.Params), params)
	}
	if err := man.Validate(params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.Params = paramsStr(params)
	if err := h.Store.Update(id, body.Name, body.Type, body.Params); err != nil {
		h.Log.Error("acme_providers: update", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: mis à jour", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ACMEProvidersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.Delete(id); err != nil {
		h.Log.Error("acme_providers: delete", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: supprimé", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// maskProviderEntry masque les paramètres secrets selon le manifeste du type. Un type inconnu
// (entrée ancienne) est renvoyé tel quel : on ne sait pas quels champs sont secrets.
func maskProviderEntry(e acme.ProviderEntry) acme.ProviderEntry {
	if man, ok := acme.DNSProviderManifest(e.Type); ok {
		e.Params = paramsStr(man.Mask(paramsAny(e.Params)))
	}
	return e
}

func paramsAny(p map[string]string) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

func paramsStr(p map[string]any) map[string]string {
	out := make(map[string]string, len(p))
	for k, v := range p {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// ACMEProviderTypesHandler GET /api/v1/acme/provider-types : manifestes des fournisseurs DNS
// (paramètres, secrets, requis, variable d'environnement). Source des formulaires de l'Admin.
type ACMEProviderTypesHandler struct{}

func (ACMEProviderTypesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, acme.DNSProviderManifests())
}
