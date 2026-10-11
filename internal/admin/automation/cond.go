// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"fmt"
)

// evalCond évalue un arbre de conditions. Les variables des configurations sont résolues dans scope (une
// condition d'étape « si » peut viser {{detail.proxy_id}}).
//   - all : toutes vraies ; les détails se cumulent (le dernier l'emporte), et detail.conditions les garde un par un.
//   - any : la première vraie, avec son détail.
//   - not : vraie quand la condition enfant est fausse ; pas de détail.
func (s *Service) evalCond(ctx context.Context, c *Cond, scope map[string]any) (bool, map[string]any, error) {
	switch {
	case c == nil:
		return false, nil, fmt.Errorf("condition absente")
	case len(c.All) > 0:
		merged := map[string]any{}
		var each []any
		for i := range c.All {
			ok, d, err := s.evalCond(ctx, &c.All[i], scope)
			if err != nil || !ok {
				return false, nil, err
			}
			for k, v := range d {
				merged[k] = v
			}
			each = append(each, d)
		}
		merged["conditions"] = each
		return true, merged, nil
	case len(c.Any) > 0:
		var firstErr error
		for i := range c.Any {
			ok, d, err := s.evalCond(ctx, &c.Any[i], scope)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if ok {
				return true, d, nil
			}
		}
		return false, nil, firstErr
	case c.Not != nil:
		ok, _, err := s.evalCond(ctx, c.Not, scope)
		if err != nil {
			return false, nil, err
		}
		return !ok, map[string]any{}, nil
	}
	mod, _, ok := condRegistry.Lookup(c.Type)
	if !ok {
		return false, nil, fmt.Errorf("condition inconnue : %q", c.Type)
	}
	matched, detail, err := mod.eval(ctx, s, resolveMap(c.Config, scope))
	if matched && detail == nil {
		detail = map[string]any{}
	}
	return matched, detail, err
}

// EvalCondition évalue une condition hors de tout flux (tests, diagnostic).
func (s *Service) EvalCondition(ctx context.Context, c *Cond) (bool, map[string]any, error) {
	return s.evalCond(ctx, c, map[string]any{})
}
