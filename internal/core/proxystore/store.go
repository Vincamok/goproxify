// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	ProdDirName      = "proxies"
	RevisionsDirName = "proxies-revisions"
)

var (
	// ErrNotFound is returned when a proxy or revision file is missing.
	ErrNotFound = errors.New("proxystore: not found")

	hostSafeRe = regexp.MustCompile(`[^a-z0-9._-]+`)
)

// Store persists proxy envelopes as flat JSON files under a Core data root.
type Store struct {
	basePath string
}

// New creates a Store rooted at basePath (typically /etc/goproxify).
func New(basePath string) *Store {
	return &Store{basePath: basePath}
}

// BasePath returns the Core data root.
func (s *Store) BasePath() string { return s.basePath }

// ProdDir returns the directory listing all production proxies.
func (s *Store) ProdDir() string {
	return filepath.Join(s.basePath, ProdDirName)
}

// RevisionsDir returns the pipeline revisions directory.
func (s *Store) RevisionsDir() string {
	return filepath.Join(s.basePath, RevisionsDirName)
}

// EnsureDirs creates proxies/ and proxies-revisions/ if needed.
func (s *Store) EnsureDirs() error {
	for _, dir := range []string{s.ProdDir(), s.RevisionsDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("proxystore: mkdir %s: %w", dir, err)
		}
	}
	return nil
}

// SanitizeHost turns a hostname into a safe filename stem (without .json).
// Empty host (TCP/UDP) falls back to id-based naming via ProdFilename.
func SanitizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = hostSafeRe.ReplaceAllString(h, "_")
	h = strings.Trim(h, "._-")
	for strings.Contains(h, "__") {
		h = strings.ReplaceAll(h, "__", "_")
	}
	return h
}

// ProdFilename returns the basename for a production proxy file.
func ProdFilename(host, id string) string {
	stem := SanitizeHost(host)
	if stem == "" {
		stem = "tcp_" + sanitizeID(id)
	}
	return stem + ".yaml"
}

// RevisionFilename returns the basename for a revision file: <id>--<rev>.yaml
func RevisionFilename(id, rev string) string {
	return sanitizeID(id) + "--" + sanitizeID(rev) + ".yaml"
}

func sanitizeID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	return out
}

// ProdPath returns the absolute path for a production envelope.
func (s *Store) ProdPath(host, id string) string {
	return filepath.Join(s.ProdDir(), ProdFilename(host, id))
}

// RevisionPath returns the absolute path for a revision envelope.
func (s *Store) RevisionPath(id, rev string) string {
	return filepath.Join(s.RevisionsDir(), RevisionFilename(id, rev))
}

// WriteProd writes a production envelope (status forced to production).
func (s *Store) WriteProd(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("proxystore: envelope nil")
	}
	cp := *env
	cp.Status = StatusProduction
	cp.Revision = ""
	cp.DryRun = nil
	if cp.SchemaVersion == 0 {
		cp.SchemaVersion = SchemaVersionV1
	}
	if err := cp.Validate(); err != nil {
		return err
	}
	if err := s.EnsureDirs(); err != nil {
		return err
	}
	path := s.ProdPath(cp.Host, cp.ID)
	if err := atomicWriteJSON(path, &cp); err != nil {
		return err
	}
	// Remove legacy .json file if we just wrote .yaml (avoids duplicates in listDir).
	if strings.HasSuffix(path, ".yaml") {
		_ = os.Remove(strings.TrimSuffix(path, ".yaml") + ".json")
	}
	return nil
}

// WriteRevision writes a pipeline revision envelope.
func (s *Store) WriteRevision(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("proxystore: envelope nil")
	}
	if env.SchemaVersion == 0 {
		env.SchemaVersion = SchemaVersionV1
	}
	// StatusProduction is allowed on a revision file as audit trail after promote
	// (Revision field must remain set — enforced below).
	if env.Status == StatusProduction && env.Revision == "" {
		return fmt.Errorf("proxystore: revision requise pour audit production")
	}
	if err := env.Validate(); err != nil {
		return err
	}
	if err := s.EnsureDirs(); err != nil {
		return err
	}
	return atomicWriteJSON(s.RevisionPath(env.ID, env.Revision), env)
}

// ReadProdFile reads a production file by absolute or relative path under ProdDir.
func (s *Store) ReadProdFile(name string) (*Envelope, error) {
	path := name
	if !filepath.IsAbs(name) {
		path = filepath.Join(s.ProdDir(), name)
	}
	return readEnvelope(path)
}

// ReadProdByHostID reads production by host+id (filename derivation).
func (s *Store) ReadProdByHostID(host, id string) (*Envelope, error) {
	return readEnvelope(s.ProdPath(host, id))
}

// ReadProdByID scans production files for a matching id.
func (s *Store) ReadProdByID(id string) (*Envelope, error) {
	list, err := s.ListProd()
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, ErrNotFound
}

// ReadRevision reads a revision by proxy id and revision id.
func (s *Store) ReadRevision(id, rev string) (*Envelope, error) {
	return readEnvelope(s.RevisionPath(id, rev))
}

// ListProd lists all production envelopes (sorted by filename).
func (s *Store) ListProd() ([]*Envelope, error) {
	return s.listDir(s.ProdDir(), true)
}

// ListRevisions lists revision envelopes. If proxyID is non-empty, filters by id.
func (s *Store) ListRevisions(proxyID string) ([]*Envelope, error) {
	all, err := s.listDir(s.RevisionsDir(), false)
	if err != nil {
		return nil, err
	}
	if proxyID == "" {
		return all, nil
	}
	out := make([]*Envelope, 0)
	for _, e := range all {
		if e.ID == proxyID {
			out = append(out, e)
		}
	}
	return out, nil
}

// DeleteProd removes the production file for host+id.
func (s *Store) DeleteProd(host, id string) error {
	return removeFile(s.ProdPath(host, id))
}

// DeleteProdByID finds and deletes the production file for id.
func (s *Store) DeleteProdByID(id string) error {
	env, err := s.ReadProdByID(id)
	if err != nil {
		return err
	}
	return s.DeleteProd(env.Host, env.ID)
}

// DeleteRevision removes a revision file.
func (s *Store) DeleteRevision(id, rev string) error {
	return removeFile(s.RevisionPath(id, rev))
}

// RemoveProdIfHostChanged deletes the old prod file when host rename changes the filename.
func (s *Store) RemoveProdIfHostChanged(oldHost, newHost, id string) error {
	oldPath := s.ProdPath(oldHost, id)
	newPath := s.ProdPath(newHost, id)
	if oldPath == newPath {
		return nil
	}
	return removeFile(oldPath)
}

func (s *Store) listDir(dir string, requireProdStatus bool) ([]*Envelope, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []*Envelope{}, nil
		}
		return nil, fmt.Errorf("proxystore: list %s: %w", dir, err)
	}
	out := make([]*Envelope, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".json")) {
			continue
		}
		env, err := readEnvelope(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if requireProdStatus && env.Status != StatusProduction {
			// Still include but normalize? Prefer returning as-is for visibility.
		}
		out = append(out, env)
	}
	return out, nil
}

// readEnvelope reads a YAML envelope file. If the .yaml path does not exist
// and the caller passed a .yaml path, it falls back to the equivalent .json
// path to support legacy installations.
func readEnvelope(path string) (*Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && strings.HasSuffix(path, ".yaml") {
			jsonPath := strings.TrimSuffix(path, ".yaml") + ".json"
			data, err = os.ReadFile(jsonPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil, ErrNotFound
				}
				return nil, fmt.Errorf("proxystore: read %s: %w", jsonPath, err)
			}
			return parseEnvelopeJSON(jsonPath, data)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("proxystore: read %s: %w", path, err)
	}
	if strings.HasSuffix(path, ".json") {
		return parseEnvelopeJSON(path, data)
	}
	return parseEnvelopeYAML(path, data)
}

func parseEnvelopeJSON(path string, data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("proxystore: parse %s: %w", path, err)
	}
	return &env, nil
}

// envelopeYAML is the YAML-friendly representation of Envelope.
// Config is stored as a raw YAML node and converted to/from json.RawMessage.
type envelopeYAML struct {
	SchemaVersion int            `yaml:"schema_version"`
	ID            string         `yaml:"id"`
	Revision      string         `yaml:"revision,omitempty"`
	Host          string         `yaml:"host"`
	Enabled       bool           `yaml:"enabled"`
	Status        Status         `yaml:"status"`
	CreatedAt     *timeWrapper   `yaml:"created_at,omitempty"`
	UpdatedAt     timeWrapper    `yaml:"updated_at"`
	CreatedBy     string         `yaml:"created_by,omitempty"`
	DryRun        *DryRunResult  `yaml:"dry_run,omitempty"`
	Config        yaml.Node      `yaml:"config"`
}

// timeWrapper lets time.Time round-trip through yaml as RFC3339.
type timeWrapper struct{ T time.Time }

func (tw timeWrapper) MarshalYAML() (any, error)  { return tw.T.UTC().Format(time.RFC3339Nano), nil }
func (tw *timeWrapper) UnmarshalYAML(v *yaml.Node) error {
	t, err := time.Parse(time.RFC3339Nano, v.Value)
	if err != nil {
		return err
	}
	tw.T = t
	return nil
}

func parseEnvelopeYAML(path string, data []byte) (*Envelope, error) {
	var y envelopeYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("proxystore: parse %s: %w", path, err)
	}
	// Convert the config YAML node back to JSON so the rest of the app is unchanged.
	var configAny any
	if err := y.Config.Decode(&configAny); err != nil {
		return nil, fmt.Errorf("proxystore: config decode %s: %w", path, err)
	}
	configJSON, err := json.Marshal(configAny)
	if err != nil {
		return nil, fmt.Errorf("proxystore: config marshal %s: %w", path, err)
	}
	env := &Envelope{
		SchemaVersion: y.SchemaVersion,
		ID:            y.ID,
		Revision:      y.Revision,
		Host:          y.Host,
		Enabled:       y.Enabled,
		Status:        y.Status,
		UpdatedAt:     y.UpdatedAt.T,
		CreatedBy:     y.CreatedBy,
		DryRun:        y.DryRun,
		Config:        json.RawMessage(configJSON),
	}
	if y.CreatedAt != nil {
		env.CreatedAt = &y.CreatedAt.T
	}
	return env, nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("proxystore: delete %s: %w", path, err)
	}
	return nil
}

// marshalEnvelope serialises env as YAML (or JSON for legacy .json paths).
func marshalEnvelope(path string, env *Envelope) ([]byte, error) {
	if strings.HasSuffix(path, ".json") {
		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("proxystore: marshal: %w", err)
		}
		return append(data, '\n'), nil
	}
	// Convert Config (json.RawMessage) to a generic map so yaml.v3 can encode it.
	var configAny any
	if err := json.Unmarshal(env.Config, &configAny); err != nil {
		return nil, fmt.Errorf("proxystore: config unmarshal: %w", err)
	}
	y := envelopeYAML{
		SchemaVersion: env.SchemaVersion,
		ID:            env.ID,
		Revision:      env.Revision,
		Host:          env.Host,
		Enabled:       env.Enabled,
		Status:        env.Status,
		UpdatedAt:     timeWrapper{env.UpdatedAt},
		CreatedBy:     env.CreatedBy,
		DryRun:        env.DryRun,
	}
	if env.CreatedAt != nil {
		tw := timeWrapper{*env.CreatedAt}
		y.CreatedAt = &tw
	}
	// Encode configAny into y.Config YAML node.
	if err := y.Config.Encode(configAny); err != nil {
		return nil, fmt.Errorf("proxystore: config encode: %w", err)
	}
	data, err := yaml.Marshal(&y)
	if err != nil {
		return nil, fmt.Errorf("proxystore: marshal yaml: %w", err)
	}
	return data, nil
}

// MigrateResult reports the outcome of a single file migration.
type MigrateResult struct {
	JSON string // source .json path
	YAML string // destination .yaml path
	Err  error
}

// MigrateJSONToYAML converts all .json files in proxies/ and proxies-revisions/
// to .yaml and removes the originals. Already-.yaml files are skipped.
// Returns one MigrateResult per .json file found.
func (s *Store) MigrateJSONToYAML() []MigrateResult {
	var results []MigrateResult
	for _, dir := range []string{s.ProdDir(), s.RevisionsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			results = append(results, MigrateResult{Err: fmt.Errorf("proxystore: list %s: %w", dir, err)})
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".json") {
				continue
			}
			jsonPath := filepath.Join(dir, name)
			yamlPath := strings.TrimSuffix(jsonPath, ".json") + ".yaml"
			res := MigrateResult{JSON: jsonPath, YAML: yamlPath}

			env, err := readEnvelope(jsonPath)
			if err != nil {
				res.Err = err
				results = append(results, res)
				continue
			}
			if err := atomicWriteJSON(yamlPath, env); err != nil {
				res.Err = err
				results = append(results, res)
				continue
			}
			if err := os.Remove(jsonPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				res.Err = fmt.Errorf("proxystore: remove %s: %w", jsonPath, err)
			}
			results = append(results, res)
		}
	}
	return results
}

func atomicWriteJSON(path string, env *Envelope) error {
	data, err := marshalEnvelope(path, env)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("proxystore: mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-proxy-*")
	if err != nil {
		return fmt.Errorf("proxystore: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("proxystore: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("proxystore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("proxystore: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("proxystore: rename: %w", err)
	}
	return nil
}
