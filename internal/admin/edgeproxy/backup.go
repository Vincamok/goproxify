// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"net/http"
	"time"
)

// BackupBundle : fichiers d'état d'une passerelle, chemin relatif → contenu.
type BackupBundle struct {
	Files   map[string][]byte `json:"files"`
	Skipped []string          `json:"skipped,omitempty"` // chemin (raison)
	Sizes   map[string]int64  `json:"sizes,omitempty"`
}

// BackupResult : réponse d'une passerelle à une restauration.
type BackupResult struct {
	Written         int      `json:"written"`
	Rejected        []string `json:"rejected"`
	RestartRequired bool     `json:"restart_required"`
}

// NewBackupClient : client à délai long (l'état d'une passerelle peut peser plusieurs dizaines de Mo).
func NewBackupClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Minute}}
}

// BackupExport récupère l'état persisté de la passerelle.
func (c *Client) BackupExport(ctx context.Context, t Target) (*BackupBundle, error) {
	var out BackupBundle
	if err := c.do(ctx, t, http.MethodGet, "/internal/v1/backup/export", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BackupRestore réécrit l'état de la passerelle ; elle doit ensuite être redémarrée.
func (c *Client) BackupRestore(ctx context.Context, t Target, b *BackupBundle) (*BackupResult, error) {
	var out BackupResult
	if err := c.do(ctx, t, http.MethodPost, "/internal/v1/backup/restore", b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
