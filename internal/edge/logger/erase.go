// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// EraseIP supprime du fichier d'access log et de ses rotations les lignes d'une IP (droit à
// l'effacement RGPD) et retourne leur nombre. Les lignes d'un client dont l'IP était déjà tronquée
// ne portent pas l'IP réelle : elles n'ont rien à effacer. Sans fichier (stdout), il n'y a rien à faire.
// Les écritures sont suspendues pendant la réécriture ; celles que le canal ne peut pas absorber sont
// perdues, comme quand le journal est saturé.
func (a *AccessLogger) EraseIP(ip string) (int, error) {
	target := CanonicalIP(ip)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.path == "" {
		return 0, nil
	}
	// Fermer d'abord : on ne remplace pas un fichier ouvert (Windows), et le writer garderait l'ancien descripteur.
	if a.closer != nil {
		a.closer.Close() //nolint:errcheck
	}
	defer a.reopenLocked()
	dir, base := filepath.Dir(a.path), filepath.Base(a.path)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"
	files := []string{a.path}
	for _, pattern := range []string{prefix + "*" + ext, prefix + "*" + ext + ".gz"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return 0, err
		}
		files = append(files, m...)
	}

	total := 0
	for _, f := range files {
		n, err := eraseIPFromFile(f, target)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func eraseIPFromFile(path, target string) (int, error) {
	src, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer src.Close()
	var in io.Reader = src
	gz := strings.HasSuffix(path, ".gz")
	if gz {
		zr, err := gzip.NewReader(src)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		in = zr
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".erase-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	var out io.Writer = tmp
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(tmp)
		out = zw
	}

	removed := 0
	r := bufio.NewReader(in)
	for {
		line, rerr := r.ReadBytes('\n')
		if len(line) > 0 {
			if lineIsIP(line, target) {
				removed++
			} else if _, err := out.Write(line); err != nil {
				tmp.Close()
				return 0, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmp.Close()
			return 0, rerr
		}
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			tmp.Close()
			return 0, err
		}
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	src.Close() // Windows ne remplace pas un fichier encore ouvert
	if removed == 0 {
		return 0, nil
	}
	if info, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmp.Name(), info.Mode())
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return 0, err
	}
	return removed, nil
}

func lineIsIP(line []byte, target string) bool {
	if !bytes.Contains(line, []byte(`"remote_ip"`)) {
		return false
	}
	var e struct {
		RemoteIP string `json:"remote_ip"`
	}
	if json.Unmarshal(line, &e) != nil {
		return false
	}
	return CanonicalIP(e.RemoteIP) == target
}

// CanonicalIP normalise une adresse (IPv6 compressée, IPv4 mappée en IPv4, zone retirée) pour que
// deux écritures d'une même IP se comparent égales.
func CanonicalIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return ip
}
