// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
)

// internalAPI expose une API HTTP locale sur laquelle le Core / l'Admin poussent des commandes.
// Écoute sur :8001 (configurable). Auth Bearer obligatoire (fail-closed).
type internalAPI struct {
	port    int
	cfgPath string // chemin vers agent.json (pour l'action configure)
	mu      sync.RWMutex
	// authTokens : valeurs Bearer acceptées (pairing secret et/ou token Agent).
	authTokens []string
	lifecycle  *agentdocker.LifecycleManager
	discovery  *agentdocker.Discovery
	log        *slog.Logger
	srv        *http.Server
}

func newInternalAPI(port int, lifecycle *agentdocker.LifecycleManager, log *slog.Logger, cfgPath ...string) *internalAPI {
	if port == 0 {
		port = 8001
	}
	p := ""
	if len(cfgPath) > 0 {
		p = cfgPath[0]
	}
	return &internalAPI{port: port, cfgPath: p, lifecycle: lifecycle, log: log}
}

// setDiscovery injecte la Discovery après construction (le pairing peut survenir après New).
func (a *internalAPI) setDiscovery(d *agentdocker.Discovery) {
	a.discovery = d
}

// setAuthTokens remplace la liste des Bearer acceptés (chaînes vides ignorées).
func (a *internalAPI) setAuthTokens(tokens ...string) {
	filtered := make([]string, 0, len(tokens))
	seen := map[string]struct{}{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		filtered = append(filtered, t)
	}
	a.mu.Lock()
	a.authTokens = filtered
	a.mu.Unlock()
}

func (a *internalAPI) authorized(r *http.Request) bool {
	a.mu.RLock()
	tokens := a.authTokens
	a.mu.RUnlock()
	if len(tokens) == 0 {
		return false
	}
	provided := bearerFromRequest(r)
	if provided == "" {
		return false
	}
	pb := []byte(provided)
	for _, t := range tokens {
		tb := []byte(t)
		if len(pb) == len(tb) && subtle.ConstantTimeCompare(pb, tb) == 1 {
			return true
		}
	}
	return false
}

func bearerFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func (a *internalAPI) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/command", a.handleCommand)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	a.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", a.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	a.log.Info("agent: API interne démarrée", "port", a.port)
	go func() {
		if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error("agent: API interne", "err", err)
		}
	}()
}

// selfContainerID retourne le container ID de l'agent lui-même.
// Essaie /proc/self/cgroup (cgroups v1), puis le hostname Docker (= short container ID).
func selfContainerID() string {
	// cgroups v1 : "12:devices:/docker/<64-char-id>"
	// cgroups v2 : "0::/system.slice/docker-<64-char-id>.scope"
	if f, err := os.Open("/proc/self/cgroup"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			for _, prefix := range []string{"/docker/", "docker-"} {
				if idx := strings.Index(line, prefix); idx != -1 {
					id := line[idx+len(prefix):]
					id = strings.TrimSuffix(id, ".scope")
					if len(id) >= 12 {
						return id[:12]
					}
				}
			}
		}
	}
	// Fallback : hostname Docker = premiers 12 caractères du container ID
	if h, err := os.Hostname(); err == nil && len(h) >= 12 {
		return h
	}
	return ""
}

func (a *internalAPI) Stop(ctx context.Context) {
	if a.srv != nil {
		_ = a.srv.Shutdown(ctx)
	}
}

type commandRequest struct {
	Action    string `json:"action"`    // update | rollback | rescan
	Container string `json:"container"` // ID ou nom
	Prune     bool   `json:"prune"`
	// Pour scale
	ScaleTarget int `json:"scale_target"`
}

func (a *internalAPI) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(r) {
		http.Error(w, "non autorisé", http.StatusUnauthorized)
		return
	}
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "erreur lecture body", http.StatusBadRequest)
		return
	}
	var cmd commandRequest
	if err := json.Unmarshal(rawBody, &cmd); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	switch cmd.Action {
	case "update":
		cid := cmd.Container
		if cid == "" {
			cid = selfContainerID()
		}
		if cid == "" {
			http.Error(w, "container ID requis et auto-détection impossible", http.StatusBadRequest)
			return
		}
		go func() {
			a.log.Info("agent: commande update", "container", cid)
			if err := a.lifecycle.UpdateContainer(context.Background(), cid, cmd.Prune); err != nil {
				a.log.Error("agent: update échoué", "container", cid, "err", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "update_started"})

	case "rollback":
		go func() {
			a.log.Info("agent: commande rollback", "container", cmd.Container)
			if err := a.lifecycle.Rollback(context.Background(), cmd.Container); err != nil {
				a.log.Error("agent: rollback échoué", "container", cmd.Container, "err", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rollback_started"})

	case "rescan":
		if a.discovery == nil {
			http.Error(w, "discovery non initialisée", http.StatusServiceUnavailable)
			return
		}
		go func() {
			a.log.Info("agent: commande rescan — scan Docker forcé")
			a.discovery.ScanAll(context.Background())
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rescan_started"})

	case "configure":
		if a.cfgPath == "" {
			http.Error(w, "chemin config non configuré", http.StatusNotImplemented)
			return
		}
		var patch map[string]json.RawMessage
		if err := json.Unmarshal(rawBody, &patch); err != nil {
			http.Error(w, "JSON invalide", http.StatusBadRequest)
			return
		}
		delete(patch, "action")
		if err := a.applyConfigPatch(patch); err != nil {
			a.log.Error("agent: configure échoué", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
		go func() {
			a.log.Info("agent: configure — redémarrage pour appliquer la nouvelle config")
			os.Exit(0)
		}()

	default:
		http.Error(w, fmt.Sprintf("action inconnue : %q", cmd.Action), http.StatusBadRequest)
	}
}

// applyConfigPatch fusionne un patch JSON partiel dans agent.json et le réécrit.
func (a *internalAPI) applyConfigPatch(patch map[string]json.RawMessage) error {
	data, err := os.ReadFile(a.cfgPath)
	if err != nil {
		return fmt.Errorf("lecture %s: %w", a.cfgPath, err)
	}
	var current map[string]json.RawMessage
	if err := json.Unmarshal(data, &current); err != nil {
		return fmt.Errorf("parsing %s: %w", a.cfgPath, err)
	}
	for k, v := range patch {
		current[k] = v
	}
	out, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.cfgPath), ".configure-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	tmp.Sync() //nolint:errcheck
	tmp.Close()
	return os.Rename(tmpName, a.cfgPath)
}
