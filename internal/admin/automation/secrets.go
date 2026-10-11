// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"github.com/vincamok/goproxify/internal/modules"
)

// Les secrets d'un flux sont les champs secrets de ses actions et les paramètres mot de passe de son
// modèle. Toute sortie (API, MCP, export) passe par maskFlow ; une modification passe par keepSecrets, pour
// que renvoyer le masque conserve la valeur enregistrée.

// maskFlow retourne une copie de f dont les secrets sont masqués.
func maskFlow(f *Flow) *Flow {
	out := cloneFlow(f)
	walkSteps(out.Steps, func(st *Step) {
		if st.Action == nil {
			return
		}
		if _, man, ok := actionRegistry.Lookup(st.Action.Type); ok && st.Action.Config != nil {
			st.Action.Config = man.Mask(st.Action.Config)
		}
	})
	out.Origin.Params = maskParams(out.Origin)
	return out
}

func templateParamsManifest(o Origin) (modules.Manifest, bool) {
	if o.Kind != OriginTemplate {
		return modules.Manifest{}, false
	}
	tpl, ok := templateByID(o.TemplateID)
	if !ok {
		return modules.Manifest{}, false
	}
	return modules.Manifest{Type: tpl.ID, Label: tpl.Name, Fields: tpl.Params}, true
}

func maskParams(o Origin) map[string]any {
	if man, ok := templateParamsManifest(o); ok && o.Params != nil {
		return man.Mask(o.Params)
	}
	return o.Params
}

// keepSecrets complète next avec les secrets de old quand next les omet ou renvoie le masque. Une action est
// retrouvée par l'identifiant de son étape et doit garder le même type : une étape déplacée garde ses secrets,
// une étape dont l'action change doit les ressaisir.
func keepSecrets(old, next *Flow) {
	prev := map[string]*Node{}
	walkSteps(old.Steps, func(st *Step) {
		if st.Action != nil {
			prev[st.ID] = st.Action
		}
	})
	walkSteps(next.Steps, func(st *Step) {
		o := prev[st.ID]
		if st.Action == nil || o == nil || o.Type != st.Action.Type {
			return
		}
		if _, man, ok := actionRegistry.Lookup(st.Action.Type); ok {
			st.Action.Config = man.KeepSecrets(o.Config, st.Action.Config)
		}
	})
	if next.Origin.Kind == OriginTemplate && old.Origin.TemplateID == next.Origin.TemplateID {
		if man, ok := templateParamsManifest(next.Origin); ok {
			next.Origin.Params = man.KeepSecrets(old.Origin.Params, next.Origin.Params)
		}
	}
}

// cloneFlow copie un flux en profondeur (passage par JSON : les configurations sont du JSON).
func cloneFlow(f *Flow) *Flow {
	var out Flow
	copyJSON(f, &out)
	out.State = f.State
	return &out
}
