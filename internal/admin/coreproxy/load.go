// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package coreproxy

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/vincamok/goproxify/internal/core/proxystore"
	"github.com/vincamok/goproxify/internal/core/router"
)

// LoadProductionEnvelopes loads unique production envelopes.
// Mode files: from all Core targets. Mode sqlite: from Admin DB.
func LoadProductionEnvelopes(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	if FilesEnabled() {
		return loadFromCores(ctx, db)
	}
	return loadFromSQLite(ctx, db, false)
}

// LoadEnabledEnvelopes is like LoadProductionEnvelopes but only enabled=true.
func LoadEnabledEnvelopes(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	if FilesEnabled() {
		all, err := loadFromCores(ctx, db)
		if err != nil {
			return nil, err
		}
		out := make([]*proxystore.Envelope, 0, len(all))
		for _, e := range all {
			if e != nil && e.Enabled {
				out = append(out, e)
			}
		}
		return out, nil
	}
	return loadFromSQLite(ctx, db, true)
}

// LoadEnabledRoutes parses enabled envelopes into router.Route.
func LoadEnabledRoutes(ctx context.Context, db *sql.DB) ([]*router.Route, error) {
	envs, err := LoadEnabledEnvelopes(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]*router.Route, 0, len(envs))
	for _, e := range envs {
		var route router.Route
		if json.Unmarshal(e.Config, &route) != nil {
			continue
		}
		if route.ID == "" {
			route.ID = e.ID
		}
		out = append(out, &route)
	}
	return out, nil
}

func loadFromCores(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	targets, err := ListTargets(ctx, db)
	if err != nil {
		return nil, err
	}
	client := NewClient()
	byID := map[string]*proxystore.Envelope{}
	for _, t := range targets {
		res, err := client.List(ctx, t)
		if err != nil {
			continue
		}
		for _, e := range res.Production {
			if e != nil {
				byID[e.ID] = e
			}
		}
	}
	out := make([]*proxystore.Envelope, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	return out, nil
}

func loadFromSQLite(ctx context.Context, db *sql.DB, enabledOnly bool) ([]*proxystore.Envelope, error) {
	q := `SELECT id, name, config, enabled, created_at, updated_at FROM proxies`
	if enabledOnly {
		q += ` WHERE enabled=1`
	}
	q += ` ORDER BY name`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*proxystore.Envelope, 0)
	for rows.Next() {
		var id, name, cfg string
		var enabled int
		var created, updated sql.NullTime
		if rows.Scan(&id, &name, &cfg, &enabled, &created, &updated) != nil {
			continue
		}
		env := &proxystore.Envelope{
			SchemaVersion: proxystore.SchemaVersionV1,
			ID:            id,
			Host:          name,
			Enabled:       enabled == 1,
			Status:        proxystore.StatusProduction,
			Config:        json.RawMessage(cfg),
		}
		if updated.Valid {
			env.UpdatedAt = updated.Time
		}
		if created.Valid {
			t := created.Time
			env.CreatedAt = &t
		}
		out = append(out, env)
	}
	return out, nil
}
