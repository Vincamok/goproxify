// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/plugins"
)

// Dépôts de plugins (ADR 0008). Un dépôt est une URL qui sert un index JSON :
//
//	{ "version": 1, "name": "Mon dépôt",
//	  "plugins": [ { "name", "version", "description", "homepage",
//	                 "manifest": {…}, "wasm_url": "https://…/plugin.wasm" (ou relative à l'index),
//	                 "sha256": "…", "signature": "…" (Ed25519 en base64, facultative) } ] }
//
// Installer depuis un dépôt suit exactement la même politique qu'une installation manuelle : empreinte vérifiée,
// module compilé et contrat contrôlé, signature exigée dès qu'une clé de confiance est enregistrée. Un dépôt
// ne confère donc aucune confiance : il ne fait que livrer des paquets.
const (
	maxRepoIndexBytes = 1 << 20
	repoFetchTimeout  = 15 * time.Second
	maxRepoParallel   = 4
)

// PluginReposHandler gère les dépôts de plugins et l'installation depuis un dépôt. Admin uniquement.
type PluginReposHandler struct {
	DB      *sql.DB
	Log     *slog.Logger
	Plugins *PluginsHandler
}

// PluginRepo est un dépôt enregistré.
type PluginRepo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	AllowPrivate bool      `json:"allow_private"`
	CreatedAt    time.Time `json:"created_at"`
}

type repoIndex struct {
	Version int         `json:"version"`
	Name    string      `json:"name"`
	Plugins []repoEntry `json:"plugins"`
}

type repoEntry struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Description string           `json:"description,omitempty"`
	Homepage    string           `json:"homepage,omitempty"`
	Manifest    plugins.Manifest `json:"manifest"`
	WasmURL     string           `json:"wasm_url"`
	SHA256      string           `json:"sha256"`
	Signature   string           `json:"signature,omitempty"`
}

// CatalogEntry est une entrée du catalogue agrégé de tous les dépôts.
type CatalogEntry struct {
	RepoID           string   `json:"repo_id"`
	RepoName         string   `json:"repo_name"`
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Description      string   `json:"description,omitempty"`
	Homepage         string   `json:"homepage,omitempty"`
	Hooks            []string `json:"hooks"`
	SHA256           string   `json:"sha256"`
	Signed           bool     `json:"signed"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	UpdateAvailable  bool     `json:"update_available"`
}

func (h *PluginReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/plugin-repos"), "/")
	switch {
	case r.Method == http.MethodGet && rest == "":
		h.list(w, r)
	case r.Method == http.MethodPost && rest == "":
		h.add(w, r)
	case r.Method == http.MethodGet && rest == "catalog":
		h.catalog(w, r)
	case r.Method == http.MethodPost && rest == "install":
		h.install(w, r)
	case r.Method == http.MethodDelete && rest != "" && rest != "catalog" && rest != "install":
		h.remove(w, r, rest)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func loadRepos(ctx context.Context, db *sql.DB) ([]PluginRepo, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, name, url, allow_private, created_at FROM plugin_repos ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginRepo{}
	for rows.Next() {
		var r PluginRepo
		var priv int
		if err := rows.Scan(&r.ID, &r.Name, &r.URL, &priv, &r.CreatedAt); err == nil {
			r.AllowPrivate = priv == 1
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func (h *PluginReposHandler) list(w http.ResponseWriter, r *http.Request) {
	repos, err := loadRepos(r.Context(), h.DB)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, repos)
}

// checkRepoURL : un dépôt se sert en HTTPS ; le HTTP clair et les adresses internes exigent allow_private.
func checkRepoURL(raw string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, errors.New("URL invalide")
	}
	if u.Scheme != "https" && !(allowPrivate && u.Scheme == "http") {
		return nil, errors.New("une URL https est requise (http uniquement avec allow_private)")
	}
	if !allowPrivate && plugins.BlockedHost(u.Hostname()) {
		return nil, errors.New("adresse interne refusée (allow_private pour un dépôt interne)")
	}
	return u, nil
}

func (h *PluginReposHandler) add(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		URL          string `json:"url"`
		AllowPrivate bool   `json:"allow_private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	if _, err := checkRepoURL(req.URL, req.AllowPrivate); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	priv := 0
	if req.AllowPrivate {
		priv = 1
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO plugin_repos (id, name, url, allow_private) VALUES (?, ?, ?, ?)`, id, name, strings.TrimSpace(req.URL), priv); err != nil {
		http.Error(w, "ce dépôt est déjà enregistré", http.StatusConflict)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "create", "plugin_repo:"+id, name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(PluginRepo{ID: id, Name: name, URL: strings.TrimSpace(req.URL), AllowPrivate: req.AllowPrivate, CreatedAt: time.Now().UTC()})
}

func (h *PluginReposHandler) remove(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM plugin_repos WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "dépôt introuvable", http.StatusNotFound)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "delete", "plugin_repo:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}

// get télécharge une URL de dépôt avec le client protégé (adresses internes refusées, redirections bornées).
func (h *PluginReposHandler) get(ctx context.Context, repo PluginRepo, u string, limit int64) ([]byte, error) {
	parsed, err := checkRepoURL(u, repo.AllowPrivate)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := plugins.SafeHTTPClientFollow(repoFetchTimeout, repo.AllowPrivate).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statut HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("réponse de plus de %d octets", limit)
	}
	return body, nil
}

func (h *PluginReposHandler) fetchIndex(ctx context.Context, repo PluginRepo) (*repoIndex, error) {
	body, err := h.get(ctx, repo, repo.URL, maxRepoIndexBytes)
	if err != nil {
		return nil, err
	}
	var idx repoIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("index illisible : %w", err)
	}
	if idx.Version != 1 {
		return nil, fmt.Errorf("version d'index %d non prise en charge (attendu 1)", idx.Version)
	}
	return &idx, nil
}

// versionLess compare deux versions « 1.2.3 » numériquement, champ par champ (repli : ordre lexicographique).
func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := "0", "0" // un champ absent vaut 0 : 1.0 = 1.0.0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		if ex == nil && ey == nil {
			if nx != ny {
				return nx < ny
			}
			continue
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func installedVersions(ctx context.Context, db *sql.DB) map[string]string {
	out := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT manifest FROM plugins`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var m plugins.Manifest
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &m) == nil {
			out[m.Name] = m.Version
		}
	}
	return out
}

func (h *PluginReposHandler) catalog(w http.ResponseWriter, r *http.Request) {
	repos, err := loadRepos(r.Context(), h.DB)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if want := r.URL.Query().Get("repo"); want != "" {
		var keep []PluginRepo
		for _, rp := range repos {
			if rp.ID == want {
				keep = append(keep, rp)
			}
		}
		repos = keep
	}
	installed := installedVersions(r.Context(), h.DB)
	var (
		mu      sync.Mutex
		entries = []CatalogEntry{}
		errs    = []map[string]string{}
		wg      sync.WaitGroup
		sem     = make(chan struct{}, maxRepoParallel)
	)
	for _, repo := range repos {
		wg.Add(1)
		go func(repo PluginRepo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			idx, err := h.fetchIndex(r.Context(), repo)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, map[string]string{"repo_id": repo.ID, "repo_name": repo.Name, "error": err.Error()})
				return
			}
			for _, e := range idx.Plugins {
				ce := CatalogEntry{
					RepoID: repo.ID, RepoName: repo.Name, Name: e.Name, Version: e.Version, Description: e.Description,
					Homepage: e.Homepage, Hooks: e.Manifest.Hooks, SHA256: e.SHA256, Signed: e.Signature != "",
				}
				if v, ok := installed[e.Name]; ok {
					ce.InstalledVersion = v
					ce.UpdateAvailable = versionLess(v, e.Version)
				}
				entries = append(entries, ce)
			}
		}(repo)
	}
	wg.Wait()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return versionLess(entries[j].Version, entries[i].Version) // plus récente d'abord
	})
	jsonOK(w, map[string]any{"entries": entries, "errors": errs})
}

func (h *PluginReposHandler) install(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoID  string `json:"repo_id"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RepoID == "" || req.Name == "" {
		http.Error(w, "repo_id et name requis", http.StatusBadRequest)
		return
	}
	repos, _ := loadRepos(r.Context(), h.DB)
	var repo *PluginRepo
	for i := range repos {
		if repos[i].ID == req.RepoID {
			repo = &repos[i]
		}
	}
	if repo == nil {
		http.Error(w, "dépôt introuvable", http.StatusNotFound)
		return
	}
	// L'index est relu côté serveur : le client ne fournit jamais l'URL du module à télécharger.
	idx, err := h.fetchIndex(r.Context(), *repo)
	if err != nil {
		http.Error(w, "index du dépôt : "+err.Error(), http.StatusBadGateway)
		return
	}
	var entry *repoEntry
	for i := range idx.Plugins {
		e := &idx.Plugins[i]
		if e.Name != req.Name || (req.Version != "" && e.Version != req.Version) {
			continue
		}
		if entry == nil || versionLess(entry.Version, e.Version) {
			entry = e
		}
	}
	if entry == nil {
		http.Error(w, "plugin introuvable dans ce dépôt", http.StatusNotFound)
		return
	}
	if entry.Manifest.Name != entry.Name || entry.Manifest.Version != entry.Version {
		http.Error(w, "entrée incohérente : le manifeste ne porte pas le nom et la version annoncés", http.StatusBadGateway)
		return
	}
	base, _ := url.Parse(repo.URL)
	ref, err := url.Parse(entry.WasmURL)
	if err != nil {
		http.Error(w, "wasm_url invalide", http.StatusBadGateway)
		return
	}
	wasm, err := h.get(r.Context(), *repo, base.ResolveReference(ref).String(), maxPluginWasmBytes)
	if err != nil {
		http.Error(w, "téléchargement du module : "+err.Error(), http.StatusBadGateway)
		return
	}
	_, replacing := installedVersions(r.Context(), h.DB)[entry.Name]
	name := ""
	if replacing {
		name = entry.Name
	}
	info, created, ierr := h.Plugins.installPackage(r.Context(), pluginRequest{Manifest: entry.Manifest, SHA256: entry.SHA256, Wasm: wasm, Signature: entry.Signature}, name)
	if ierr != nil {
		http.Error(w, ierr.msg, ierr.status)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(info)
}
