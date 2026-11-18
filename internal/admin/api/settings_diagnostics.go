// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// DiagnosticsProfilingKey : réglage (table settings) qui autorise le téléchargement des profils du runtime.
const DiagnosticsProfilingKey = "diagnostics.profiling_enabled"

const (
	maxProfileSeconds     = 60
	defaultProfileSeconds = 30
)

// DiagnosticsSettingsHandler : GET/PUT /api/v1/settings/diagnostics (état du runtime et interrupteur du profilage)
// et GET /api/v1/settings/diagnostics/profile (profil du runtime, seulement quand le profilage est activé).
type DiagnosticsSettingsHandler struct {
	DB  *sql.DB
	Log *slog.Logger

	started time.Time
	cpuBusy atomic.Bool
}

// NewDiagnosticsSettingsHandler crée le gestionnaire ; started sert à l'ancienneté du processus.
func NewDiagnosticsSettingsHandler(db *sql.DB, log *slog.Logger) *DiagnosticsSettingsHandler {
	return &DiagnosticsSettingsHandler{DB: db, Log: log, started: time.Now()}
}

func (h *DiagnosticsSettingsHandler) enabled() bool {
	var v string
	if h.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, DiagnosticsProfilingKey).Scan(&v) != nil {
		return false
	}
	return v == "1"
}

func (h *DiagnosticsSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/settings/diagnostics"), "/")
	switch {
	case path == "" && r.Method == http.MethodGet:
		h.get(w)
	case path == "" && r.Method == http.MethodPut:
		h.put(w, r)
	case path == "profile" && r.Method == http.MethodGet:
		h.profile(w, r)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

type runtimeStats struct {
	GoVersion      string  `json:"go_version"`
	NumCPU         int     `json:"num_cpu"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	Goroutines     int     `json:"goroutines"`
	HeapInuseBytes uint64  `json:"heap_inuse_bytes"`
	HeapIdleBytes  uint64  `json:"heap_idle_bytes"`
	HeapRelBytes   uint64  `json:"heap_released_bytes"`
	StackBytes     uint64  `json:"stack_bytes"`
	SysBytes       uint64  `json:"sys_bytes"`
	NextGCBytes    uint64  `json:"next_gc_bytes"`
	MemLimitBytes  int64   `json:"mem_limit_bytes,omitempty"`
	NumGC          uint32  `json:"num_gc"`
	GCCPUFraction  float64 `json:"gc_cpu_fraction"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
}

func (h *DiagnosticsSettingsHandler) stats() runtimeStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := runtimeStats{
		GoVersion: runtime.Version(), NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		Goroutines: runtime.NumGoroutine(), HeapInuseBytes: m.HeapInuse, HeapIdleBytes: m.HeapIdle,
		HeapRelBytes: m.HeapReleased, StackBytes: m.StackInuse, SysBytes: m.Sys, NextGCBytes: m.NextGC,
		NumGC: m.NumGC, GCCPUFraction: m.GCCPUFraction, UptimeSeconds: int64(time.Since(h.started).Seconds()),
	}
	// -1 lit la limite sans la changer ; MaxInt64 signifie « aucune ».
	if lim := debug.SetMemoryLimit(-1); lim < math.MaxInt64 {
		s.MemLimitBytes = lim
	}
	return s
}

func (h *DiagnosticsSettingsHandler) get(w http.ResponseWriter) {
	jsonOK(w, map[string]any{"profiling_enabled": h.enabled(), "runtime": h.stats()})
}

func (h *DiagnosticsSettingsHandler) put(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProfilingEnabled *bool `json:"profiling_enabled"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if err != nil || json.Unmarshal(raw, &body) != nil || body.ProfilingEnabled == nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	v := "0"
	if *body.ProfilingEnabled {
		v = "1"
	}
	if _, err := h.DB.Exec(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
		DiagnosticsProfilingKey, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("diagnostic : profilage du runtime", "enabled", *body.ProfilingEnabled)
	h.get(w)
}

// profile sert un profil du runtime. heap, allocs et goroutine acceptent format=text (lisible, collable dans un
// ticket) ; cpu ne se sert qu'en pprof (go tool pprof -top <fichier>) et dure `seconds` secondes.
func (h *DiagnosticsSettingsHandler) profile(w http.ResponseWriter, r *http.Request) {
	if !h.enabled() {
		http.Error(w, "profilage désactivé : l'activer dans Paramètres › Diagnostic", http.StatusForbidden)
		return
	}
	kind := r.URL.Query().Get("type")
	text := r.URL.Query().Get("format") == "text"
	switch kind {
	case "cpu":
		h.cpu(w, r)
	case "heap", "allocs", "goroutine":
		p := pprof.Lookup(kind)
		if kind == "heap" {
			runtime.GC() // sans cela, le tas affiché date du dernier cycle
		}
		if text {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			p.WriteTo(w, 1) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="goproxify-admin-%s.pb.gz"`, kind))
		p.WriteTo(w, 0) //nolint:errcheck
	default:
		http.Error(w, "type attendu : cpu, heap, allocs ou goroutine", http.StatusBadRequest)
	}
}

func (h *DiagnosticsSettingsHandler) cpu(w http.ResponseWriter, r *http.Request) {
	secs, _ := strconv.Atoi(r.URL.Query().Get("seconds"))
	if secs <= 0 {
		secs = defaultProfileSeconds
	}
	secs = min(secs, maxProfileSeconds)
	if !h.cpuBusy.CompareAndSwap(false, true) {
		http.Error(w, "un profil CPU est déjà en cours", http.StatusConflict)
		return
	}
	defer h.cpuBusy.Store(false)
	// Le serveur borne l'écriture d'une réponse à 30 s : un profil plus long serait coupé.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(secs)*time.Second + 30*time.Second))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="goproxify-admin-cpu.pb.gz"`)
	if err := pprof.StartCPUProfile(w); err != nil {
		w.Header().Del("Content-Disposition")
		http.Error(w, "profil CPU impossible : "+err.Error(), http.StatusConflict)
		return
	}
	// Le profil n'est écrit qu'à la fin de la capture : sans en-têtes envoyés tout de suite, une passerelle devant
	// l'Admin (30 s d'attente d'en-têtes par défaut) coupe la requête en 502 avant la fin.
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	select {
	case <-time.After(time.Duration(secs) * time.Second):
	case <-r.Context().Done():
	}
	pprof.StopCPUProfile()
}
