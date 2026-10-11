// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/vincamok/goproxify/internal/modules"
)

//go:embed templates/templates.yaml
var templateFS embed.FS

// Template est un modèle de flux paramétrable.
type Template struct {
	ID          string          `json:"id" yaml:"id"`
	Category    string          `json:"category" yaml:"category"`
	Version     int             `json:"version" yaml:"version"`
	Name        string          `json:"name" yaml:"name"`
	Description string          `json:"description" yaml:"description"`
	Kind        TriggerKind     `json:"kind" yaml:"-"`
	Params      []modules.Field `json:"params" yaml:"params"`
	Flow        map[string]any  `json:"flow" yaml:"flow"`
}

var (
	templatesOnce sync.Once
	templatesList []Template
	templatesErr  error
)

// Templates retourne les modèles intégrés.
func Templates() ([]Template, error) {
	templatesOnce.Do(func() {
		raw, err := templateFS.ReadFile("templates/templates.yaml")
		if err != nil {
			templatesErr = err
			return
		}
		var list []Template
		if err := yaml.Unmarshal(raw, &list); err != nil {
			templatesErr = fmt.Errorf("modèles illisibles : %w", err)
			return
		}
		for i := range list {
			list[i].Flow = normalizeJSON(list[i].Flow)
			if t, ok := list[i].Flow["trigger"].(map[string]any); ok {
				list[i].Kind = TriggerKind(cfgStr(t, "kind"))
			}
			if list[i].Params == nil {
				list[i].Params = []modules.Field{}
			}
		}
		templatesList = list
	})
	return templatesList, templatesErr
}

func templateByID(id string) (Template, bool) {
	list, _ := Templates()
	for _, t := range list {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

func (t Template) paramsManifest() modules.Manifest {
	return modules.Manifest{Type: t.ID, Label: t.Name, Fields: t.Params}
}

// render construit le flux d'un modèle avec ses paramètres (valeurs par défaut pour les absents). Le flux
// rendu reste à valider.
func (t Template) render(params map[string]any) (*Flow, map[string]any, error) {
	p := normalizeJSON(params)
	for _, f := range t.Params {
		if v, ok := p[f.Key]; (!ok || v == nil || v == "") && f.Default != nil {
			p[f.Key] = f.Default
		}
	}
	p = normalizeJSON(p)
	if err := t.paramsManifest().Validate(p); err != nil {
		return nil, nil, invalid("paramètres : %v", err)
	}
	for _, f := range t.Params {
		if f.Kind == modules.KindPassword && p[f.Key] == modules.Masque {
			return nil, nil, invalid("paramètres : %s est masqué, saisissez sa valeur", f.Key)
		}
	}
	rendered := resolve(t.Flow, map[string]any{"param": p})
	b, _ := json.Marshal(rendered)
	var f Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, invalid("modèle %s : paramètre de type inattendu (%v)", t.ID, err)
	}
	f.Name, f.Description = t.Name, t.Description
	f.Origin = Origin{Kind: OriginTemplate, TemplateID: t.ID, TemplateVersion: t.Version, Params: p}
	return &f, p, nil
}
