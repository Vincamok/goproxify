// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"reflect"
	"testing"
)

func kinds(changes []Change) []string {
	var out []string
	for _, c := range changes {
		k := c.Kind
		if c.StepID != "" {
			k += ":" + c.StepID
		}
		out = append(out, k)
	}
	return out
}

func TestDiffFlows(t *testing.T) {
	base := func() *Flow {
		return &Flow{Name: "f", Enabled: true, Trigger: Trigger{Kind: TriggerManual},
			Steps: []Step{act("a", "1"), act("b", "2"), {ID: "c", Type: StepIf, Condition: &Cond{Type: "test_cond"},
				Then: []Step{act("d", "3")}}, act("e", "4")}}
	}
	for name, c := range map[string]struct {
		edit func(*Flow)
		want []string
	}{
		"identique":         {func(*Flow) {}, nil},
		"nom et activation": {func(f *Flow) { f.Name, f.Enabled = "g", false }, []string{"name", "enabled"}},
		"déclencheur": {func(f *Flow) {
			f.Trigger = Trigger{Kind: TriggerSchedule, Schedule: &ScheduleTrigger{Cron: "0 3 * * *"}}
		},
			[]string{"trigger_kind"}},
		"garde-fou":   {func(f *Flow) { f.Guard.CooldownSec = 60 }, []string{"guard"}},
		"insertion":   {func(f *Flow) { f.Steps = append([]Step{act("x", "0")}, f.Steps...) }, []string{"step_added:x"}},
		"retrait":     {func(f *Flow) { f.Steps = append(f.Steps[:1], f.Steps[2:]...) }, []string{"step_removed:b"}},
		"modif":       {func(f *Flow) { f.Steps[1].Action.Config["value"] = "deux" }, []string{"step_changed:b"}},
		"permutation": {func(f *Flow) { f.Steps[0], f.Steps[1] = f.Steps[1], f.Steps[0] }, []string{"step_moved:a"}},
		"dans une branche": {func(f *Flow) {
			f.Steps[2].Then = nil
			f.Steps[2].Else = []Step{act("d", "3")}
		}, []string{"step_moved:d"}},
		// Le contenu d'un « si » n'est pas une modification du « si » lui-même.
		"branche seule": {func(f *Flow) { f.Steps[2].Then = append(f.Steps[2].Then, act("z", "9")) }, []string{"step_added:z"}},
	} {
		next := base()
		c.edit(next)
		if got := kinds(diffFlows(base(), next)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s : %v, attendu %v", name, got, c.want)
		}
	}
}

func TestVersionsCarryChanges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := e.create(manual("v", act("a", "un")))
	if _, err := e.s.Update(ctx, f.ID, manual("v", act("a", "deux"), act("b", "trois")), "test"); err != nil {
		t.Fatal(err)
	}
	vs, err := e.s.Versions(ctx, f.ID)
	if err != nil || len(vs) != 2 {
		t.Fatalf("versions : %v %v", vs, err)
	}
	if got := kinds(vs[0].Changes); !reflect.DeepEqual(got, []string{"step_changed:a", "step_added:b"}) {
		t.Errorf("v2 : %v", got)
	}
	if got := kinds(vs[1].Changes); !reflect.DeepEqual(got, []string{"created"}) {
		t.Errorf("v1 : %v", got)
	}
}

func TestTemplateDriftAndPreviewChanges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f, err := e.s.Install(ctx, "ban-spike-notify", TemplateUpdate{Enabled: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if f.Template == nil || f.Template.Outdated || f.Template.Missing || f.Template.CurrentVersion != 1 {
		t.Fatalf("modèle à jour : %+v", f.Template)
	}
	// Flux installé avec une version antérieure du modèle.
	if _, err := e.s.db.Exec(`UPDATE flows SET origin_json=json_set(origin_json,'$.template_version',0) WHERE id=?`, f.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := e.s.Get(ctx, f.ID)
	if got.Template == nil || !got.Template.Outdated {
		t.Fatalf("modèle changé depuis l'installation non signalé : %+v", got.Template)
	}
	res, err := e.s.Preview(ctx, "ban-spike-notify", map[string]any{"count": 80, "window": "1h"}, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(res.Changes); !reflect.DeepEqual(k, []string{"trigger", "params"}) {
		t.Errorf("aperçu des changements : %v", k)
	}
	if _, err := e.s.Preview(ctx, "cve-high-notify", nil, f.ID); err == nil {
		t.Error("aperçu d'un autre modèle accepté pour ce flux")
	}
	if _, err := e.s.UpdateParams(ctx, f.ID, TemplateUpdate{Name: f.Name, Enabled: true, Params: map[string]any{"count": 80}}, "test"); err != nil {
		t.Fatal(err)
	}
	got, _ = e.s.Get(ctx, f.ID)
	if got.Template.Outdated {
		t.Error("réenregistrer les paramètres doit appliquer la version courante du modèle")
	}
	if _, err := e.s.db.Exec(`UPDATE flows SET origin_json=json_set(origin_json,'$.template_id','disparu') WHERE id=?`, f.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.s.Get(ctx, f.ID); got.Template == nil || !got.Template.Missing {
		t.Errorf("modèle disparu non signalé : %+v", got.Template)
	}
}
