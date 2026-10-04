// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pilote SQLite pour la copie cohérente des bases
)

const (
	maxBackupFileBytes  = 64 << 20
	maxBackupTotalBytes = 256 << 20
)

// backupSkipDirs : dossiers de l'état de la passerelle qu'une sauvegarde ne reprend pas
// (téléchargeables ou purement runtime).
var backupSkipDirs = map[string]bool{"geoip": true, "logs": true, "threat-lists": true, "restore-tmp": true}

func edgeDataDir() string {
	if d := os.Getenv("GPX_EDGE_DATA_DIR"); d != "" {
		return d
	}
	return "/etc/goproxify"
}

func backupSkipFile(name string) bool {
	return strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".mmdb") ||
		strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") || strings.HasSuffix(name, ".cast.gpx")
}

// backupBundle : fichiers d'état d'une passerelle, chemin relatif → contenu.
type backupBundle struct {
	Files   map[string][]byte `json:"files"`
	Skipped []string          `json:"skipped,omitempty"`
}

// collectBackupFiles lit l'état persisté de la passerelle (proxies, révisions, copies chiffrées
// *.gpx, bases SQLite, identité…). Les bases SQLite sont copiées par VACUUM INTO (cohérent à chaud).
func collectBackupFiles(root string) (*backupBundle, error) {
	b := &backupBundle{Files: map[string][]byte{}}
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		if d.IsDir() {
			if backupSkipDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if backupSkipFile(d.Name()) {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() > maxBackupFileBytes || total+info.Size() > maxBackupTotalBytes {
			b.Skipped = append(b.Skipped, rel)
			return nil
		}
		var data []byte
		if strings.HasSuffix(d.Name(), ".db") {
			data, err = vacuumCopy(p)
		} else {
			data, err = os.ReadFile(p)
		}
		if err != nil {
			b.Skipped = append(b.Skipped, rel)
			return nil
		}
		total += int64(len(data))
		b.Files[rel] = data
		return nil
	})
	return b, err
}

func vacuumCopy(path string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "gpx-vacuum-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	dst := filepath.Join(dir, "copy.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		return nil, err
	}
	return os.ReadFile(dst)
}

// safeRestorePath refuse tout chemin absolu, remontant, ou visant un dossier exclu.
func safeRestorePath(root, rel string) (string, bool) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.Contains(rel, "\\") {
		return "", false
	}
	if backupSkipDirs[strings.SplitN(filepath.ToSlash(clean), "/", 2)[0]] || backupSkipFile(filepath.Base(clean)) {
		return "", false
	}
	return filepath.Join(root, clean), true
}

func writeRestoredFile(dst string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".restore-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if strings.HasSuffix(dst, ".db") { // un -wal/-shm périmé corromprait la base restaurée
		os.Remove(dst + "-wal")
		os.Remove(dst + "-shm")
	}
	return os.Rename(tmp.Name(), dst)
}

// handleBackupExport : GET /internal/v1/backup/export — état persisté de la passerelle (appelé par l'Admin).
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	b, err := collectBackupFiles(edgeDataDir())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b) //nolint:errcheck
}

// handleBackupRestore : POST /internal/v1/backup/restore — réécrit les fichiers d'état. Un
// redémarrage de la passerelle est nécessaire pour qu'elle les relise.
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var b backupBundle
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<20)).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	root := edgeDataDir()
	written, rejected := 0, []string{}
	for rel, data := range b.Files {
		dst, ok := safeRestorePath(root, rel)
		if !ok {
			rejected = append(rejected, rel)
			continue
		}
		if err := writeRestoredFile(dst, data); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s (%v)", rel, err))
			continue
		}
		written++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"written": written, "rejected": rejected, "restart_required": true}) //nolint:errcheck
}
