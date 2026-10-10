// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"encoding/json"
	"fmt"
)

// Les actions à secret (webhook signé, PagerDuty…) rangent leurs paramètres sous « params » ; le manifeste de
// chaque action déclare lesquels sont secrets. Une règle, une planification ou une étape de playbook est relue
// par de nombreuses sorties (API, MCP, export) : toutes passent par les fonctions ci-dessous, qui remplacent les
// secrets par le masque, et les modifications repassent par KeepAction*/KeepSteps* pour que renvoyer le masque
// conserve la valeur enregistrée.

// MaskActionMap masque les secrets d'une action représentée en map JSON.
func MaskActionMap(a map[string]any) map[string]any {
	if a == nil {
		return nil
	}
	typ, _ := a["type"].(string)
	_, man, ok := actionRegistry.Lookup(typ)
	if !ok {
		return a
	}
	return man.Mask(a)
}

// MaskAction masque les secrets d'une action.
func MaskAction(a Action) Action {
	var m map[string]any
	b, _ := json.Marshal(a)
	if json.Unmarshal(b, &m) != nil {
		return a
	}
	masked := MaskActionMap(m)
	b, _ = json.Marshal(masked)
	var out Action
	if json.Unmarshal(b, &out) != nil {
		return a
	}
	return out
}

// KeepActionSecretsMap complète une action modifiée avec les secrets de l'action enregistrée quand elle les
// omet ou renvoie le masque. Les secrets d'un autre type d'action n'ont pas le même sens : rien n'est repris.
func KeepActionSecretsMap(old, next map[string]any) map[string]any {
	if old == nil || next == nil {
		return next
	}
	ot, _ := old["type"].(string)
	nt, _ := next["type"].(string)
	if ot != nt {
		return next
	}
	_, man, ok := actionRegistry.Lookup(nt)
	if !ok {
		return next
	}
	return man.KeepSecrets(old, next)
}

// KeepActionSecrets est KeepActionSecretsMap pour des actions typées.
func KeepActionSecrets(old, next Action) Action {
	var om, nm map[string]any
	ob, _ := json.Marshal(old)
	nb, _ := json.Marshal(next)
	if json.Unmarshal(ob, &om) != nil || json.Unmarshal(nb, &nm) != nil {
		return next
	}
	merged := KeepActionSecretsMap(om, nm)
	b, _ := json.Marshal(merged)
	var out Action
	if json.Unmarshal(b, &out) != nil {
		return next
	}
	return out
}

// KeepActionJSON est KeepActionSecrets sur de l'action sérialisée (anciennes valeurs en base).
func KeepActionJSON(oldRaw, nextRaw []byte) []byte {
	var om, nm map[string]any
	if json.Unmarshal(oldRaw, &om) != nil || json.Unmarshal(nextRaw, &nm) != nil {
		return nextRaw
	}
	b, err := json.Marshal(KeepActionSecretsMap(om, nm))
	if err != nil {
		return nextRaw
	}
	return b
}

// MaskActionRaw masque les secrets d'une action sérialisée ; une valeur illisible est renvoyée telle quelle.
func MaskActionRaw(raw []byte) []byte {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return raw
	}
	b, err := json.Marshal(MaskActionMap(m))
	if err != nil {
		return raw
	}
	return b
}

// MaskStepsRaw masque les secrets des actions d'un tableau d'étapes de playbook sérialisé.
func MaskStepsRaw(raw []byte) []byte {
	var steps []map[string]any
	if json.Unmarshal(raw, &steps) != nil {
		return raw
	}
	for _, st := range steps {
		if a, ok := st["action"].(map[string]any); ok {
			st["action"] = MaskActionMap(a)
		}
	}
	b, err := json.Marshal(steps)
	if err != nil {
		return raw
	}
	return b
}

// KeepStepsSecrets complète les étapes modifiées avec les secrets des étapes enregistrées, étape par étape
// (même position, même type d'action). Une étape déplacée ou changée d'action doit retaper son secret.
func KeepStepsSecrets(oldRaw, nextRaw []byte) []byte {
	var os, ns []map[string]any
	if json.Unmarshal(oldRaw, &os) != nil || json.Unmarshal(nextRaw, &ns) != nil {
		return nextRaw
	}
	for i, st := range ns {
		na, ok := st["action"].(map[string]any)
		if !ok || i >= len(os) {
			continue
		}
		if oa, ok := os[i]["action"].(map[string]any); ok {
			st["action"] = KeepActionSecretsMap(oa, na)
		}
	}
	b, err := json.Marshal(ns)
	if err != nil {
		return nextRaw
	}
	return b
}

// ValidateStepsJSON valide les actions d'un tableau d'étapes de playbook sérialisé : type connu, champs requis,
// secrets non masqués (une étape qui porte encore le masque n'a jamais reçu sa valeur).
func ValidateStepsJSON(raw []byte) error {
	var steps []struct {
		Type   string          `json:"type"`
		Action json.RawMessage `json:"action"`
	}
	if err := json.Unmarshal(raw, &steps); err != nil {
		return err
	}
	for i, st := range steps {
		if st.Type != "action" {
			continue
		}
		if err := ValidateActionJSON(st.Action); err != nil {
			return fmt.Errorf("étape %d : %w", i+1, err)
		}
	}
	return nil
}
