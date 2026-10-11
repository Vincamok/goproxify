// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Change est une différence entre deux versions d'un flux. Kind dit ce qui a changé ; l'interface et le CLI
// en font une phrase. Les valeurs ne sont pas reprises : une version porte des secrets.
type Change struct {
	Kind   string `json:"kind"` // name | description | enabled | trigger_kind | trigger | guard | origin | params | step_added | step_removed | step_changed | step_moved
	StepID string `json:"step_id,omitempty"`
	// Detail : type de l'étape (ou de son action) pour une étape ; clés touchées pour un garde-fou ou des paramètres.
	Detail string `json:"detail,omitempty"`
}

type stepAt struct {
	step   Step
	parent string // liste qui contient l'étape : « » (racine), « s3.then », « s3.else »
	index  int
	order  int // rang dans l'ordre du document
}

func flattenSteps(steps []Step, parent string, out map[string]stepAt) {
	for i, st := range steps {
		out[st.ID] = stepAt{step: st, parent: parent, index: i, order: len(out)}
		flattenSteps(st.Then, st.ID+".then", out)
		flattenSteps(st.Else, st.ID+".else", out)
	}
}

// movedSteps retourne les étapes déplacées : changées de liste, ou dont l'ordre relatif aux autres étapes
// conservées de la même liste a changé. Une étape insérée ou retirée ne déplace pas les suivantes.
func movedSteps(before, after map[string]stepAt) map[string]bool {
	moved := map[string]bool{}
	lists := map[string][]string{} // liste → étapes conservées, dans le nouvel ordre
	for id, a := range after {
		b, ok := before[id]
		if !ok {
			continue
		}
		if b.parent != a.parent {
			moved[id] = true
			continue
		}
		lists[a.parent] = append(lists[a.parent], id)
	}
	for _, ids := range lists {
		sort.Slice(ids, func(i, j int) bool { return after[ids[i]].index < after[ids[j]].index })
		// Plus longue sous-suite croissante des anciennes positions : ces étapes n'ont pas bougé.
		n := len(ids)
		length, prevIdx := make([]int, n), make([]int, n)
		best := -1
		for i := range ids {
			length[i], prevIdx[i] = 1, -1
			for j := 0; j < i; j++ {
				if before[ids[j]].index < before[ids[i]].index && length[j]+1 > length[i] {
					length[i], prevIdx[i] = length[j]+1, j
				}
			}
			if best < 0 || length[i] > length[best] {
				best = i
			}
		}
		stay := map[string]bool{}
		for i := best; i >= 0; i = prevIdx[i] {
			stay[ids[i]] = true
		}
		for _, id := range ids {
			if !stay[id] {
				moved[id] = true
			}
		}
	}
	return moved
}

func stepKind(st Step) string {
	if st.Type == StepAction && st.Action != nil {
		return st.Action.Type
	}
	return st.Type
}

// sameJSON compare deux valeurs par leur forme JSON (les configurations relues de la base et celles d'une
// requête n'ont pas toujours les mêmes types numériques).
func sameJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	var va, vb any
	_ = json.Unmarshal(ja, &va)
	_ = json.Unmarshal(jb, &vb)
	return reflect.DeepEqual(va, vb)
}

func changedKeys(a, b any) string {
	ma, mb := normalizeJSON(a), normalizeJSON(b)
	var keys []string
	seen := map[string]bool{}
	for k := range ma {
		seen[k] = true
	}
	for k := range mb {
		seen[k] = true
	}
	for k := range seen {
		if !sameJSON(ma[k], mb[k]) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}

// diffFlows liste ce qui distingue next de prev.
func diffFlows(prev, next *Flow) []Change {
	var out []Change
	if prev.Name != next.Name {
		out = append(out, Change{Kind: "name"})
	}
	if prev.Description != next.Description {
		out = append(out, Change{Kind: "description"})
	}
	if prev.Enabled != next.Enabled {
		out = append(out, Change{Kind: "enabled", Detail: fmt.Sprint(next.Enabled)})
	}
	if prev.Trigger.Kind != next.Trigger.Kind {
		out = append(out, Change{Kind: "trigger_kind", Detail: string(next.Trigger.Kind)})
	} else if !sameJSON(prev.Trigger, next.Trigger) {
		out = append(out, Change{Kind: "trigger"})
	}
	if !sameJSON(prev.Guard, next.Guard) {
		out = append(out, Change{Kind: "guard", Detail: changedKeys(prev.Guard, next.Guard)})
	}
	if prev.Origin.Kind != next.Origin.Kind || prev.Origin.TemplateID != next.Origin.TemplateID {
		out = append(out, Change{Kind: "origin", Detail: next.Origin.Kind})
	} else if !sameJSON(prev.Origin.Params, next.Origin.Params) {
		out = append(out, Change{Kind: "params", Detail: changedKeys(prev.Origin.Params, next.Origin.Params)})
	}
	before, after := map[string]stepAt{}, map[string]stepAt{}
	flattenSteps(prev.Steps, "", before)
	flattenSteps(next.Steps, "", after)
	var ids []string
	for id := range after {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return after[ids[i]].order < after[ids[j]].order })
	moved := movedSteps(before, after)
	for _, id := range ids {
		a := after[id]
		b, existed := before[id]
		if !existed {
			out = append(out, Change{Kind: "step_added", StepID: id, Detail: stepKind(a.step)})
			continue
		}
		own := func(st Step) Step { st.Then, st.Else = nil, nil; return st }
		if !sameJSON(own(b.step), own(a.step)) {
			out = append(out, Change{Kind: "step_changed", StepID: id, Detail: stepKind(a.step)})
		}
		if moved[id] {
			out = append(out, Change{Kind: "step_moved", StepID: id, Detail: stepKind(a.step)})
		}
	}
	var gone []string
	for id := range before {
		if _, ok := after[id]; !ok {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		out = append(out, Change{Kind: "step_removed", StepID: id, Detail: stepKind(before[id].step)})
	}
	return out
}
