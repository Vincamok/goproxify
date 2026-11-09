// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// API du coffre (ADR 0025) : la base de logins de l'utilisateur et leur liaison aux destinations. Les logins préconfigurés
// (SharedLogin) y figurent en lecture seule, sans rien de secret.

var (
	errNoLogin            = errors.New("aucun login lié à cette destination")
	errLoginRequired      = errors.New("plusieurs logins s'appliquent")
	errLoginNotApplicable = errors.New("login non applicable à cette destination")
)

// resolvedLogin est le login retenu pour une session, secret ouvert.
type resolvedLogin struct {
	Choice   LoginChoice
	Username string
	Secret   LoginSecret
}

func personalTargetLoginID(targetID string) string { return "t-" + targetID }

func addUnique(list []string, id string) []string {
	for _, e := range list {
		if e == id {
			return list
		}
	}
	return append(list, id)
}

func removeID(list []string, id string) []string {
	out := list[:0:0]
	for _, e := range list {
		if e != id {
			out = append(out, e)
		}
	}
	return out
}

func cleanDestIDs(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range in {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// applicableLogins liste les logins que l'utilisateur peut employer sur la destination : ses logins personnels liés, et les
// logins préconfigurés liés dont il a le droit d'usage. L'appelant a déjà vérifié que la destination lui est visible.
func (h *HTTPServer) applicableLogins(pt portalToken, destID string) ([]LoginChoice, VaultPayload, error) {
	vault, err := LoadVault(h.store, pt.UserID, pt.VaultKey)
	if err != nil {
		return nil, VaultPayload{}, err
	}
	tags := h.userTags(pt.UserID)
	var out []LoginChoice
	for _, l := range h.store.SharedLogins() {
		if l.LinksTo(destID) && l.UsableBy(pt.Username, tags) {
			out = append(out, LoginChoice{Ref: LoginRef(LoginShared, l.ID), Origin: LoginShared, Name: l.Name, Username: l.Username})
		}
	}
	for _, l := range vault.LinksTo(destID) {
		out = append(out, LoginChoice{Ref: LoginRef(LoginPersonal, l.ID), Origin: LoginPersonal, Name: l.Name, Username: l.Username})
	}
	def := vault.Defaults[destID]
	for i := range out {
		out[i].Default = out[i].Ref == def
	}
	sortChoices(out)
	return out, vault, nil
}

// resolveLogin choisit le login d'une session. wantRef vide : le seul login applicable, sinon le favori de l'utilisateur
// pour cette destination, sinon errLoginRequired (l'interface demande).
func (h *HTTPServer) resolveLogin(pt portalToken, destID, wantRef string) (resolvedLogin, []LoginChoice, error) {
	choices, vault, err := h.applicableLogins(pt, destID)
	if err != nil {
		return resolvedLogin{}, nil, err
	}
	var pick *LoginChoice
	switch {
	case wantRef != "":
		for i := range choices {
			if choices[i].Ref == wantRef {
				pick = &choices[i]
			}
		}
		if pick == nil {
			return resolvedLogin{}, choices, errLoginNotApplicable
		}
	case len(choices) == 0:
		return resolvedLogin{}, nil, errNoLogin
	case len(choices) == 1:
		pick = &choices[0]
	case choices[0].Default:
		pick = &choices[0]
	default:
		return resolvedLogin{}, choices, errLoginRequired
	}

	origin, id := ParseLoginRef(pick.Ref)
	res := resolvedLogin{Choice: *pick, Username: strings.TrimSpace(pick.Username)}
	switch origin {
	case LoginShared:
		l, ok := h.store.FindSharedLogin(id)
		if !ok {
			return resolvedLogin{}, choices, errLoginNotApplicable
		}
		secret, err := OpenLoginSecret(loginSealSecrets(h.masterSecret), l.Sealed)
		if err != nil {
			return resolvedLogin{}, choices, err
		}
		res.Secret = secret
	case LoginPersonal:
		l, ok := vault.Logins[id]
		if !ok {
			return resolvedLogin{}, choices, errLoginNotApplicable
		}
		res.Secret = LoginSecret{Password: l.Password, PrivateKey: l.PrivateKey}
	default:
		return resolvedLogin{}, choices, errLoginNotApplicable
	}
	if res.Username == "" {
		return resolvedLogin{}, choices, errors.New("le login n'a pas d'identifiant SSH")
	}
	if res.Secret.Empty() {
		return resolvedLogin{}, choices, errors.New("le login n'a ni mot de passe ni clé privée")
	}
	return res, choices, nil
}

// destKnown dit si l'utilisateur peut lier un login à cette destination : une destination du catalogue qu'il voit, ou l'une de
// ses cibles personnelles.
func (h *HTTPServer) destKnown(r *http.Request, pt portalToken, id string) bool {
	if c, ok := h.store.FindCatalogTarget(id); ok {
		return h.catalogVisible(r, pt, c)
	}
	_, ok := h.store.FindPersonalTarget(pt.UserID, id)
	return ok
}

func (h *HTTPServer) handleGetVault(w http.ResponseWriter, r *http.Request, pt portalToken) {
	vault, err := LoadVault(h.store, pt.UserID, pt.VaultKey)
	if err != nil {
		http.Error(w, "vault illisible", http.StatusUnauthorized)
		return
	}
	tags := h.userTags(pt.UserID)
	shared := []SharedLoginMeta{}
	for _, l := range h.store.SharedLogins() {
		if !l.UsableBy(pt.Username, tags) {
			continue
		}
		dests := []string{}
		for _, d := range l.DestIDs {
			if c, ok := h.store.FindCatalogTarget(d); ok && h.catalogVisible(r, pt, c) {
				dests = append(dests, d)
			}
		}
		if len(dests) == 0 {
			continue // un login qui n'ouvre rien de ce que l'utilisateur voit n'a pas à s'afficher
		}
		shared = append(shared, SharedLoginMeta{ID: l.ID, Name: l.Name, Username: l.Username, DestIDs: dests})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"personal": vault.ListPersonalMeta(),
		"shared":   shared,
		"defaults": vault.Defaults,
	})
}

type vaultLoginBody struct {
	Name            string    `json:"name"`
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	PrivateKey      string    `json:"private_key"`
	ClearPassword   bool      `json:"clear_password"`
	ClearPrivateKey bool      `json:"clear_private_key"`
	DestIDs         *[]string `json:"dest_ids"`
}

func (h *HTTPServer) handleCreateVaultLogin(w http.ResponseWriter, r *http.Request, pt portalToken) {
	var body vaultLoginBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	h.saveVaultLogin(w, r, pt, "", body)
}

func (h *HTTPServer) handleUpdateVaultLogin(w http.ResponseWriter, r *http.Request, pt portalToken) {
	var body vaultLoginBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	h.saveVaultLogin(w, r, pt, r.PathValue("id"), body)
}

// saveVaultLogin crée (id vide) ou modifie un login personnel. Un secret laissé vide est conservé ; les liaisons ne changent
// que si dest_ids est fourni.
func (h *HTTPServer) saveVaultLogin(w http.ResponseWriter, r *http.Request, pt portalToken, id string, body vaultLoginBody) {
	if body.DestIDs != nil {
		ids := cleanDestIDs(*body.DestIDs)
		for _, d := range ids {
			if !h.destKnown(r, pt, d) {
				http.Error(w, "destination inconnue ou invisible : "+d, http.StatusBadRequest)
				return
			}
		}
		body.DestIDs = &ids
	}
	var saved PersonalLogin
	var fail struct {
		code int
		msg  string
	}
	h.vaultMu.Lock()
	err := UpdateVault(h.store, pt.UserID, pt.VaultKey, func(p *VaultPayload) error {
		var l PersonalLogin
		if id != "" {
			cur, ok := p.Logins[id]
			if !ok {
				fail.code, fail.msg = http.StatusNotFound, "login introuvable"
				return errors.New(fail.msg)
			}
			l = cur
		} else {
			l.ID = uuid.NewString()
		}
		if v := strings.TrimSpace(body.Username); v != "" {
			l.Username = v
		}
		if v := strings.TrimSpace(body.Name); v != "" {
			l.Name = v
		}
		if l.Name == "" {
			l.Name = l.Username
		}
		if body.ClearPassword {
			l.Password = ""
		}
		if body.ClearPrivateKey {
			l.PrivateKey = ""
		}
		if body.Password != "" {
			l.Password = body.Password
		}
		if body.PrivateKey != "" {
			l.PrivateKey = body.PrivateKey
		}
		if body.DestIDs != nil {
			l.DestIDs = *body.DestIDs
		}
		if l.Username == "" {
			fail.code, fail.msg = http.StatusBadRequest, "login SSH requis (pas l'email Access)"
			return errors.New(fail.msg)
		}
		if l.Password == "" && l.PrivateKey == "" {
			fail.code, fail.msg = http.StatusBadRequest, "mot de passe ou clé privée requis"
			return errors.New(fail.msg)
		}
		p.Logins[l.ID] = l
		saved = l
		return nil
	})
	h.vaultMu.Unlock()
	if err != nil {
		if fail.code != 0 {
			http.Error(w, fail.msg, fail.code)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	code := http.StatusOK
	if id == "" {
		code = http.StatusCreated
	}
	writeJSON(w, code, saved.meta())
}

func (h *HTTPServer) handleDeleteVaultLogin(w http.ResponseWriter, r *http.Request, pt portalToken) {
	id := r.PathValue("id")
	h.vaultMu.Lock()
	err := UpdateVault(h.store, pt.UserID, pt.VaultKey, func(p *VaultPayload) error {
		delete(p.Logins, id)
		ref := LoginRef(LoginPersonal, id)
		for dest, def := range p.Defaults {
			if def == ref {
				delete(p.Defaults, dest)
			}
		}
		return nil
	})
	h.vaultMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePutVaultDefault mémorise le login préféré d'une destination ; une référence vide l'oublie.
func (h *HTTPServer) handlePutVaultDefault(w http.ResponseWriter, r *http.Request, pt portalToken) {
	dest := r.PathValue("dest")
	var body struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.Login != "" {
		choices, _, err := h.applicableLogins(pt, dest)
		if err != nil {
			http.Error(w, "vault illisible", http.StatusUnauthorized)
			return
		}
		found := false
		for _, c := range choices {
			found = found || c.Ref == body.Login
		}
		if !found {
			http.Error(w, "ce login ne s'applique pas à cette destination", http.StatusBadRequest)
			return
		}
	}
	h.vaultMu.Lock()
	err := UpdateVault(h.store, pt.UserID, pt.VaultKey, func(p *VaultPayload) error {
		if body.Login == "" {
			delete(p.Defaults, dest)
		} else {
			p.Defaults[dest] = body.Login
		}
		return nil
	})
	h.vaultMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDestLogins liste les logins applicables à une destination, pour que l'interface propose le choix avant de créer la
// session.
func (h *HTTPServer) handleDestLogins(w http.ResponseWriter, r *http.Request, pt portalToken) {
	dest := r.PathValue("dest")
	if !h.destKnown(r, pt, dest) {
		http.Error(w, "destination introuvable", http.StatusNotFound)
		return
	}
	choices, _, err := h.applicableLogins(pt, dest)
	if err != nil {
		http.Error(w, "vault illisible", http.StatusUnauthorized)
		return
	}
	if choices == nil {
		choices = []LoginChoice{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logins": choices})
}
