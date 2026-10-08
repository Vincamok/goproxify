// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package plugins exécute des plugins WebAssembly dans une sandbox bornée (ADR 0008). Un plugin est un
// module .wasm et un manifeste ; l'hôte ne lui donne aucune capacité (ni fichiers, ni réseau, ni
// horloge) hormis un journal, plafonne sa mémoire et son temps d'exécution, et l'instancie à neuf à
// chaque appel : rien ne fuit d'une requête à l'autre.
package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/vincamok/goproxify/internal/modules"
)

// Versions et limites de l'ABI.
const (
	APIVersion = 1

	DefaultMemoryPages = 16 // 1 Mio
	MaxMemoryPages     = 256
	DefaultTimeoutMs   = 50
	MaxTimeoutMs       = 1000
	MaxIOBytes         = 64 << 10

	maxLogBytes = 1 << 10
)

// Hooks pris en charge.
const (
	HookRequest  = "request"
	HookResponse = "response"
)

// Politique d'erreur.
const (
	OnErrorDeny  = "deny"
	OnErrorAllow = "allow"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Limits borne les ressources d'un appel.
type Limits struct {
	MemoryPages uint32 `json:"memory_pages,omitempty"`
	TimeoutMs   int    `json:"timeout_ms,omitempty"`
}

// Manifest décrit un plugin.
type Manifest struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	APIVersion int             `json:"api_version"`
	Hooks      []string        `json:"hooks"`
	OnError    string          `json:"on_error,omitempty"`
	Limits     Limits          `json:"limits,omitempty"`
	Fields     []modules.Field `json:"fields,omitempty"`
}

// Normalize applique les valeurs par défaut et vérifie le manifeste.
func (m *Manifest) Normalize() error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("nom %q invalide (minuscules, chiffres, - et _, 63 caractères au plus)", m.Name)
	}
	if strings.TrimSpace(m.Version) == "" {
		return errors.New("version requise")
	}
	if m.APIVersion != APIVersion {
		return fmt.Errorf("api_version %d non prise en charge (attendu %d)", m.APIVersion, APIVersion)
	}
	if len(m.Hooks) == 0 {
		return errors.New("au moins un hook requis (request, response)")
	}
	seen := map[string]bool{}
	for _, h := range m.Hooks {
		if h != HookRequest && h != HookResponse {
			return fmt.Errorf("hook %q inconnu (request, response)", h)
		}
		if seen[h] {
			return fmt.Errorf("hook %q en double", h)
		}
		seen[h] = true
	}
	switch m.OnError {
	case "":
		m.OnError = OnErrorDeny
	case OnErrorDeny, OnErrorAllow:
	default:
		return fmt.Errorf("on_error %q invalide (deny, allow)", m.OnError)
	}
	if m.Limits.MemoryPages == 0 {
		m.Limits.MemoryPages = DefaultMemoryPages
	}
	if m.Limits.MemoryPages > MaxMemoryPages {
		return fmt.Errorf("limits.memory_pages %d dépasse %d", m.Limits.MemoryPages, MaxMemoryPages)
	}
	if m.Limits.TimeoutMs == 0 {
		m.Limits.TimeoutMs = DefaultTimeoutMs
	}
	if m.Limits.TimeoutMs < 0 || m.Limits.TimeoutMs > MaxTimeoutMs {
		return fmt.Errorf("limits.timeout_ms %d hors de 1..%d", m.Limits.TimeoutMs, MaxTimeoutMs)
	}
	mm := modules.Manifest{Type: m.Name, Label: m.Name, Fields: m.Fields}
	return mm.Check()
}

// ConfigManifest retourne le manifeste de configuration du plugin (validation, masquage des secrets).
func (m Manifest) ConfigManifest() modules.Manifest {
	return modules.Manifest{Type: m.Name, Label: m.Name, Fields: m.Fields}
}

// Has indique si le plugin déclare le hook.
func (m Manifest) Has(hook string) bool {
	for _, h := range m.Hooks {
		if h == hook {
			return true
		}
	}
	return false
}

// RequestInput est ce que reçoit le hook de requête.
type RequestInput struct {
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	Path     string              `json:"path"`
	Query    string              `json:"query"`
	Headers  map[string][]string `json:"headers"`
	ClientIP string              `json:"client_ip"`
	Config   map[string]any      `json:"config,omitempty"`
}

// ResponseInput est ce que reçoit le hook de réponse.
type ResponseInput struct {
	RequestInput
	Status          int                 `json:"status"`
	ResponseHeaders map[string][]string `json:"response_headers"`
}

// Output est la décision d'un plugin.
type Output struct {
	Action        string            `json:"action"`
	Status        int               `json:"status,omitempty"`
	Body          string            `json:"body,omitempty"`
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	RemoveHeaders []string          `json:"remove_headers,omitempty"`
	Log           string            `json:"log,omitempty"`
}

// Actions d'un plugin.
const (
	ActionAllow  = "allow"
	ActionDeny   = "deny"
	ActionModify = "modify"
)

// Plugin est un plugin chargé : module compilé une fois, instancié à chaque appel.
type Plugin struct {
	Manifest Manifest
	SHA256   string

	rt       wazero.Runtime
	compiled wazero.CompiledModule
	log      *slog.Logger
	closed   sync.Once
}

type logKey struct{}

// Load valide le manifeste, vérifie l'empreinte du .wasm (si wantSHA est renseignée), le compile et
// contrôle son contrat : exports requis, aucun import hors `gpx.log`.
func Load(ctx context.Context, m Manifest, wasm []byte, wantSHA string, log *slog.Logger) (*Plugin, error) {
	if err := m.Normalize(); err != nil {
		return nil, fmt.Errorf("manifeste : %w", err)
	}
	sum := sha256.Sum256(wasm)
	got := hex.EncodeToString(sum[:])
	if wantSHA != "" && !strings.EqualFold(wantSHA, got) {
		return nil, fmt.Errorf("empreinte SHA-256 du .wasm différente de celle attendue (%s)", got)
	}
	if log == nil {
		log = slog.Default()
	}
	cfg := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(m.Limits.MemoryPages)
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	p := &Plugin{Manifest: m, SHA256: got, rt: rt, log: log.With("plugin", m.Name)}

	if _, err := rt.NewHostModuleBuilder("gpx").
		NewFunctionBuilder().WithFunc(p.hostLog).Export("log").
		Instantiate(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("module WASM invalide : %w", err)
	}
	p.compiled = compiled
	if err := p.checkContract(); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return p, nil
}

func (p *Plugin) checkContract() error {
	for _, f := range p.compiled.ImportedFunctions() {
		mod, name, _ := f.Import()
		if mod != "gpx" || name != "log" {
			return fmt.Errorf("import non autorisé %s.%s (seul gpx.log est fourni)", mod, name)
		}
	}
	if len(p.compiled.ImportedMemories()) > 0 {
		return errors.New("import de mémoire non autorisé")
	}
	exports := p.compiled.ExportedFunctions()
	if _, ok := p.compiled.ExportedMemories()["memory"]; !ok {
		return errors.New("export `memory` manquant")
	}
	need := []string{"alloc"}
	for _, h := range p.Manifest.Hooks {
		need = append(need, "on_"+h)
	}
	for _, n := range need {
		if _, ok := exports[n]; !ok {
			return fmt.Errorf("export `%s` manquant", n)
		}
	}
	return nil
}

// hostLog est gpx.log(ptr, len) : journalise un message du plugin, borné.
func (p *Plugin) hostLog(ctx context.Context, m api.Module, ptr, n uint32) {
	if n > maxLogBytes {
		n = maxLogBytes
	}
	b, ok := m.Memory().Read(ptr, n)
	if !ok {
		return
	}
	if c, ok := ctx.Value(logKey{}).(*logCollector); ok {
		c.add(string(b))
	}
}

type logCollector struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logCollector) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buf.Len() < maxLogBytes {
		c.buf.WriteString(s)
		c.buf.WriteByte('\n')
	}
}

// Close libère le module compilé.
func (p *Plugin) Close(ctx context.Context) {
	p.closed.Do(func() { _ = p.rt.Close(ctx) })
}

// Call exécute un hook. Une erreur (échec, dépassement de temps ou de mémoire, sortie illisible)
// n'applique pas la politique on_error : c'est à l'appelant (voir Failed).
func (p *Plugin) Call(ctx context.Context, hook string, input any) (Output, error) {
	if !p.Manifest.Has(hook) {
		return Output{Action: ActionAllow}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Manifest.Limits.TimeoutMs)*time.Millisecond)
	defer cancel()
	logs := &logCollector{}
	ctx = context.WithValue(ctx, logKey{}, logs)

	in, err := json.Marshal(input)
	if err != nil {
		return Output{}, err
	}
	if len(in) > MaxIOBytes {
		return Output{}, fmt.Errorf("entrée de %d octets : plafond %d", len(in), MaxIOBytes)
	}
	mod, err := p.rt.InstantiateModule(ctx, p.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return Output{}, fmt.Errorf("instanciation : %w", err)
	}
	defer mod.Close(ctx)

	res, err := mod.ExportedFunction("alloc").Call(ctx, uint64(len(in)))
	if err != nil || len(res) != 1 {
		return Output{}, fmt.Errorf("alloc : %w", callErr(err))
	}
	ptr := uint32(res[0])
	if !mod.Memory().Write(ptr, in) {
		return Output{}, errors.New("alloc a retourné une adresse hors mémoire")
	}
	res, err = mod.ExportedFunction("on_"+hook).Call(ctx, uint64(ptr), uint64(len(in)))
	if err != nil || len(res) != 1 {
		return Output{}, fmt.Errorf("on_%s : %w", hook, callErr(err))
	}
	out, err := p.readOutput(mod, res[0])
	if l := logs.buf.String(); l != "" {
		p.log.Info("plugin: journal", "hook", hook, "message", strings.TrimSpace(l))
	}
	return out, err
}

func callErr(err error) error {
	if err == nil {
		return errors.New("résultat inattendu")
	}
	return err
}

func (p *Plugin) readOutput(mod api.Module, packed uint64) (Output, error) {
	ptr, n := uint32(packed>>32), uint32(packed)
	if n == 0 {
		return Output{Action: ActionAllow}, nil
	}
	if n > MaxIOBytes {
		return Output{}, fmt.Errorf("sortie de %d octets : plafond %d", n, MaxIOBytes)
	}
	raw, ok := mod.Memory().Read(ptr, n)
	if !ok {
		return Output{}, errors.New("sortie hors de la mémoire du plugin")
	}
	var out Output
	if err := json.Unmarshal(raw, &out); err != nil {
		return Output{}, fmt.Errorf("sortie illisible : %w", err)
	}
	return out, out.normalize()
}

// forbiddenHeaders ne peuvent pas être posés ni retirés par un plugin : ils portent le cadrage du
// message ou l'identité de la requête.
var forbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true,
}

func validHeaderName(s string) bool {
	if s == "" || forbiddenHeaders[strings.ToLower(s)] {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validHeaderValue(s string) bool {
	return !strings.ContainsAny(s, "\r\n\x00") && len(s) <= 8<<10
}

func (o *Output) normalize() error {
	switch o.Action {
	case "":
		o.Action = ActionAllow
	case ActionAllow, ActionDeny, ActionModify:
	default:
		return fmt.Errorf("action %q inconnue (allow, deny, modify)", o.Action)
	}
	if o.Action == ActionDeny {
		if o.Status == 0 {
			o.Status = 403
		}
		if o.Status < 400 || o.Status > 599 {
			return fmt.Errorf("status %d hors de 400..599", o.Status)
		}
	}
	for k, v := range o.SetHeaders {
		if !validHeaderName(k) || !validHeaderValue(v) {
			return fmt.Errorf("en-tête %q refusé", k)
		}
	}
	for _, k := range o.RemoveHeaders {
		if !validHeaderName(k) {
			return fmt.Errorf("retrait de l'en-tête %q refusé", k)
		}
	}
	return nil
}

// Evaluate exécute un hook et applique la politique d'erreur du manifeste : le résultat est toujours une
// décision exploitable. Si le plugin a échoué, err décrit l'échec (à journaliser) et la décision est un
// refus 503 (on_error = deny) ou un laisser-passer (on_error = allow).
func (p *Plugin) Evaluate(ctx context.Context, hook string, input any) (out Output, err error) {
	out, err = p.Call(ctx, hook, input)
	if err == nil {
		return out, nil
	}
	if p.Manifest.OnError == OnErrorAllow {
		return Output{Action: ActionAllow}, err
	}
	return Output{Action: ActionDeny, Status: 503, Body: "plugin indisponible"}, err
}
