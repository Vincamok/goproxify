// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logexport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Audit est le journal local des opérations sensibles sur les logs (export, gel légal). Chaque ligne porte
// l'empreinte de la précédente : retirer ou modifier une ligne casse la chaîne, que Verify détecte (une ligne
// retirée en fin de fichier ne se voit pas : la chaîne n'est pas ancrée ailleurs).
type Audit struct{ Path string }

// AuditEntry est une ligne du journal. Detail ne contient aucune IP : l'empreinte SHA-256 d'une adresse filtrée suffit.
type AuditEntry struct {
	Ts       string         `json:"ts"`
	Operator string         `json:"operator"`
	Op       string         `json:"op"`
	Detail   map[string]any `json:"detail,omitempty"`
	Prev     string         `json:"prev"`
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

func (a Audit) lastLine() ([]byte, error) {
	f, err := os.Open(a.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var last []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			last = append(last[:0], sc.Bytes()...)
		}
	}
	return last, sc.Err()
}

// Append ajoute une ligne au journal.
func (a Audit) Append(now time.Time, operator, op string, detail map[string]any) error {
	last, err := a.lastLine()
	if err != nil {
		return err
	}
	e := AuditEntry{Ts: now.UTC().Format(time.RFC3339), Operator: operator, Op: op, Detail: detail}
	if last != nil {
		e.Prev = lineHash(last)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Read rend les lignes du journal et vérifie leur chaîne.
func (a Audit) Read() ([]AuditEntry, error) {
	f, err := os.Open(a.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	prev := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return out, fmt.Errorf("journal d'audit : ligne %d illisible", n)
		}
		if e.Prev != prev {
			return out, fmt.Errorf("journal d'audit : la chaîne est rompue à la ligne %d (ligne retirée ou modifiée)", n)
		}
		prev = lineHash(line)
		out = append(out, e)
	}
	return out, sc.Err()
}
