// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// proxyIdentity est ce que create_proxy et update_proxy savent poser du nom et des étiquettes d'un proxy : ce que les
// périmètres de droits lisent (ADR 0022).
type proxyIdentity struct {
	name      string
	hasName   bool
	labels    map[string]string
	hasLabels bool
}

func parseProxyIdentity(args map[string]any) (proxyIdentity, error) {
	var id proxyIdentity
	if v, ok := args["name"]; ok {
		s, isString := v.(string)
		if !isString {
			return id, fmt.Errorf("name : texte attendu")
		}
		id.name, id.hasName = s, true
	}
	if v, ok := args["labels"]; ok {
		raw, isMap := v.(map[string]any)
		if v != nil && !isMap {
			return id, fmt.Errorf("labels : objet clé → valeur attendu")
		}
		id.labels, id.hasLabels = map[string]string{}, true
		for k, val := range raw {
			s, isString := val.(string)
			if !isString {
				return id, fmt.Errorf("labels.%s : texte attendu", k)
			}
			id.labels[k] = s
		}
	}
	if err := api.ValidateProxyIdentity(&router.Route{Name: id.name, Labels: id.labels}); err != nil {
		return id, err
	}
	return id, nil
}

// apply pose le nom et les étiquettes dans la configuration ; un nom vide ou un objet vide les retire.
func (id proxyIdentity) apply(cfg map[string]any) {
	if id.hasName {
		if id.name == "" {
			delete(cfg, "name")
		} else {
			cfg["name"] = id.name
		}
	}
	if id.hasLabels {
		if len(id.labels) == 0 {
			delete(cfg, "labels")
		} else {
			cfg["labels"] = id.labels
		}
	}
}
