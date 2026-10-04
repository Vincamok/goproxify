// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package asn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultURL est le jeu de données public ip2asn (iptoasn.com, domaine public), mis à jour toutes les heures.
const DefaultURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

const (
	downloadTimeout = 3 * time.Minute
	maxDownload     = 64 << 20
	// minRanges écarte une réponse tronquée ou une page d'erreur : le jeu réel compte plus de 700 000 plages.
	defaultMinRanges = 10000
)

// ErrNotLoaded : le jeu de données n'est pas installé et n'a pas pu être téléchargé.
var ErrNotLoaded = errors.New("base ASN indisponible")

// Info décrit la base installée.
type Info struct {
	Path      string    `json:"path"`
	URL       string    `json:"url"`
	Installed bool      `json:"installed"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	ASNs      int       `json:"asns,omitempty"`
	Ranges    int       `json:"ranges,omitempty"`
}

// Store charge le jeu de données à la demande, le télécharge s'il est absent et le recharge quand
// le fichier change.
type Store struct {
	path, url string
	minRanges int
	client    *http.Client
	log       *slog.Logger

	mu  sync.Mutex
	idx *Index
	mod time.Time
}

// NewStore retourne un Store ; path est l'emplacement du fichier .tsv.gz, url sa source.
func NewStore(path, url string, log *slog.Logger) *Store {
	if url == "" {
		url = DefaultURL
	}
	if log == nil {
		log = slog.Default()
	}
	return &Store{path: path, url: url, minRanges: defaultMinRanges, log: log, client: &http.Client{Timeout: downloadTimeout}}
}

// Index retourne l'index, en le chargeant (et en téléchargeant le fichier s'il est absent).
func (s *Store) Index(ctx context.Context) (*Index, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.downloadLocked(ctx); err != nil {
			return nil, fmt.Errorf("%w : %v", ErrNotLoaded, err)
		}
		return s.idx, nil
	}
	if s.idx != nil && st.ModTime().Equal(s.mod) {
		return s.idx, nil
	}
	idx, err := s.load()
	if err != nil {
		return nil, err
	}
	s.idx, s.mod = idx, st.ModTime()
	return idx, nil
}

// Installed retourne l'index uniquement si le fichier est déjà installé : il ne télécharge rien. Pour
// enrichir un affichage avec l'ASN d'une adresse sans déclencher un téléchargement de 9 Mo.
func (s *Store) Installed(ctx context.Context) (*Index, bool) {
	s.mu.Lock()
	installed := false
	if _, err := os.Stat(s.path); err == nil {
		installed = true
	}
	s.mu.Unlock()
	if !installed {
		return nil, false
	}
	idx, err := s.Index(ctx)
	return idx, err == nil
}

// Refresh retélécharge le jeu de données même s'il est présent.
func (s *Store) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloadLocked(ctx)
}

// Info décrit la base sans la charger.
func (s *Store) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := Info{Path: s.path, URL: s.url}
	if st, err := os.Stat(s.path); err == nil {
		in.Installed, in.UpdatedAt, in.SizeBytes = true, st.ModTime(), st.Size()
	}
	if s.idx != nil {
		in.ASNs, in.Ranges = s.idx.Len()
	}
	return in
}

func (s *Store) load() (*Index, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseGzip(f)
}

func (s *Store) downloadLocked(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("téléchargement de %s : HTTP %d", s.url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "ip2asn-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxDownload {
		return fmt.Errorf("fichier trop volumineux (plus de %d Mo)", maxDownload>>20)
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		return err
	}
	idx, err := ParseGzip(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("jeu de données illisible : %w", err)
	}
	if _, ranges := idx.Len(); ranges < s.minRanges {
		return fmt.Errorf("jeu de données incomplet (%d plages, au moins %d attendues)", ranges, s.minRanges)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	s.idx, s.mod = idx, st.ModTime()
	asns, ranges := idx.Len()
	s.log.Info("asn: base installée", "asns", asns, "ranges", ranges, "path", s.path)
	return nil
}
