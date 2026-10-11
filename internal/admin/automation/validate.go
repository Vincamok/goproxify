// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/modules"
)

const (
	maxDepth       = 5  // imbrication des si/sinon et des groupes de conditions, profondeur des appels
	maxSteps       = 50 // étapes d'un flux, branches comprises
	minIntervalSec = 30
)

var stepIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// ValidationError est une erreur de saisie (400), par opposition à une erreur interne.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// normalize complète un flux saisi : identifiants d'étape manquants, sous-objets du déclencheur hors type
// retirés, configurations passées par JSON (nombres en float64) comme à la lecture d'une requête.
func normalize(f *Flow) {
	f.Name = strings.TrimSpace(f.Name)
	t := &f.Trigger
	if t.Kind != TriggerCondition {
		t.Condition, t.IntervalSec = nil, 0
	}
	if t.Kind != TriggerEvent {
		t.Event = nil
	}
	if t.Kind != TriggerSchedule {
		t.Schedule = nil
	}
	if t.Kind != TriggerManual {
		t.Manual = nil
	}
	if f.Origin.Kind == "" {
		f.Origin.Kind = OriginManual
	}
	used := map[string]bool{}
	walkSteps(f.Steps, func(st *Step) { used[st.ID] = st.ID != "" })
	n := 0
	walkSteps(f.Steps, func(st *Step) {
		if st.ID == "" {
			for {
				n++
				id := fmt.Sprintf("s%d", n)
				if !used[id] {
					st.ID, used[id] = id, true
					break
				}
			}
		}
		if st.Config != nil {
			st.Config = normalizeJSON(st.Config)
		}
		if st.Action != nil && st.Action.Config != nil {
			st.Action.Config = normalizeJSON(st.Action.Config)
		}
		normalizeCond(st.Condition)
	})
	normalizeCond(t.Condition)
}

func normalizeCond(c *Cond) {
	if c == nil {
		return
	}
	if c.Config != nil {
		c.Config = normalizeJSON(c.Config)
	}
	for i := range c.All {
		normalizeCond(&c.All[i])
	}
	for i := range c.Any {
		normalizeCond(&c.Any[i])
	}
	normalizeCond(c.Not)
}

// validate vérifie un flux normalisé. flows contient tous les flux enregistrés (pour les appels), le flux
// validé y remplaçant sa version enregistrée.
func validate(f *Flow, flows map[string]*Flow) error {
	if f.Name == "" {
		return invalid("nom requis")
	}
	if len(f.Name) > 200 {
		return invalid("nom trop long (200 caractères au plus)")
	}
	if err := validateTrigger(&f.Trigger); err != nil {
		return err
	}
	switch f.Guard.Placement {
	case "", PlacementAuto, PlacementAdmin:
	default:
		return invalid("guard.placement : %q invalide (auto, admin)", f.Guard.Placement)
	}
	if f.Guard.CooldownSec < 0 || f.Guard.MaxConcurrent < 0 {
		return invalid("guard : valeurs négatives")
	}
	for _, v := range varsIn(f.Guard.CooldownKey) {
		if root := strings.Split(v, ".")[0]; root != "detail" && root != "flow" {
			return invalid("guard.cooldown_key : seules les variables detail.* et flow.* sont disponibles")
		}
	}
	if len(f.Steps) == 0 {
		return invalid("au moins une étape est requise")
	}
	count := 0
	seen := map[string]bool{}
	walkSteps(f.Steps, func(st *Step) { count++ })
	if count > maxSteps {
		return invalid("trop d'étapes (%d au plus)", maxSteps)
	}
	if err := validateSteps(f.Steps, 1, seen, map[string]bool{}, flows); err != nil {
		return err
	}
	return checkCallCycles(f, flows)
}

func validateTrigger(t *Trigger) error {
	switch t.Kind {
	case TriggerCondition:
		if t.Condition == nil {
			return invalid("déclencheur condition : condition requise")
		}
		if t.IntervalSec != 0 && t.IntervalSec < minIntervalSec {
			return invalid("déclencheur condition : intervalle minimal %d s", minIntervalSec)
		}
		if err := validateCond(t.Condition, 1); err != nil {
			return invalid("déclencheur : %v", err)
		}
		for _, v := range condVars(t.Condition) {
			if root := strings.Split(v, ".")[0]; root != "flow" {
				return invalid("déclencheur : la variable {{%s}} n'existe pas encore à ce stade", v)
			}
		}
	case TriggerEvent:
		if t.Event == nil || t.Event.Event == "" {
			return invalid("déclencheur événement : événement requis")
		}
		known := false
		for _, tr := range alerting.AllTriggers {
			known = known || string(tr) == t.Event.Event
		}
		if !known {
			return invalid("déclencheur événement : %q inconnu", t.Event.Event)
		}
		switch t.Event.MinSeverity {
		case "", "info", "warning", "critical":
		default:
			return invalid("déclencheur événement : gravité %q invalide", t.Event.MinSeverity)
		}
		for _, p := range append([]string{t.Event.DomainGlob}, mapValues(t.Event.Match)...) {
			if _, err := filepath.Match(p, ""); err != nil {
				return invalid("déclencheur événement : motif %q invalide", p)
			}
		}
	case TriggerSchedule:
		if t.Schedule == nil {
			return invalid("déclencheur horaire : expression cron requise")
		}
		if _, err := ParseExpr(t.Schedule.Cron); err != nil {
			return invalid("déclencheur horaire : %v", err)
		}
	case TriggerManual:
		if t.Manual != nil && len(t.Manual.Inputs) > 0 {
			if err := (modules.Manifest{Type: "inputs", Label: "inputs", Fields: t.Manual.Inputs}).Check(); err != nil {
				return invalid("paramètres du playbook : %v", err)
			}
		}
	default:
		return invalid("type de déclencheur %q inconnu (condition, event, schedule, manual)", t.Kind)
	}
	return nil
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func validateCond(c *Cond, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("conditions imbriquées trop profondément (%d niveaux au plus)", maxDepth)
	}
	kinds := 0
	for _, b := range []bool{len(c.All) > 0, len(c.Any) > 0, c.Not != nil, c.Type != ""} {
		if b {
			kinds++
		}
	}
	if kinds != 1 {
		return fmt.Errorf("une condition est soit simple (type), soit un groupe (all, any ou not)")
	}
	for i := range c.All {
		if err := validateCond(&c.All[i], depth+1); err != nil {
			return err
		}
	}
	for i := range c.Any {
		if err := validateCond(&c.Any[i], depth+1); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return validateCond(c.Not, depth+1)
	}
	if c.Type == "" {
		return nil
	}
	mod, man, ok := condRegistry.Lookup(c.Type)
	if !ok {
		return fmt.Errorf("condition inconnue : %q", c.Type)
	}
	cfg := c.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	if err := man.Validate(cfg); err != nil {
		return fmt.Errorf("condition %s : %w", c.Type, err)
	}
	if mod.check != nil {
		if err := mod.check(cfg); err != nil {
			return fmt.Errorf("condition %s : %w", c.Type, err)
		}
	}
	return nil
}

func condVars(c *Cond) []string {
	if c == nil {
		return nil
	}
	out := varsIn(c.Config)
	for i := range c.All {
		out = append(out, condVars(&c.All[i])...)
	}
	for i := range c.Any {
		out = append(out, condVars(&c.Any[i])...)
	}
	return append(out, condVars(c.Not)...)
}

// validateSteps vérifie une liste d'étapes. done contient les étapes exécutées avant cette liste (leurs
// sorties sont disponibles) ; une étape d'une branche n'est pas disponible après le si/sinon, car l'autre
// branche a pu s'exécuter à sa place.
func validateSteps(steps []Step, depth int, seen, done map[string]bool, flows map[string]*Flow) error {
	if depth > maxDepth {
		return invalid("si/sinon imbriqués trop profondément (%d niveaux au plus)", maxDepth)
	}
	avail := copySet(done)
	for i := range steps {
		st := &steps[i]
		if !stepIDRe.MatchString(st.ID) {
			return invalid("identifiant d'étape %q invalide (lettres, chiffres, - et _)", st.ID)
		}
		if seen[st.ID] {
			return invalid("identifiant d'étape %q en double", st.ID)
		}
		seen[st.ID] = true
		if err := validateStep(st, flows); err != nil {
			return invalid("étape %s : %v", st.ID, err)
		}
		for _, v := range stepVars(st) {
			if err := checkVar(v, avail); err != nil {
				return invalid("étape %s : %v", st.ID, err)
			}
		}
		if st.Type == StepIf {
			// Les branches voient le résultat de la condition ({{steps.<si>.x}}).
			inner := copySet(avail)
			inner[st.ID] = true
			if err := validateSteps(st.Then, depth+1, seen, inner, flows); err != nil {
				return err
			}
			if err := validateSteps(st.Else, depth+1, seen, inner, flows); err != nil {
				return err
			}
		} else if len(st.Then) > 0 || len(st.Else) > 0 {
			return invalid("étape %s : seules les étapes « si » ont des branches", st.ID)
		}
		avail[st.ID] = true
	}
	return nil
}

func copySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func stepVars(st *Step) []string {
	out := varsIn(st.Config)
	if st.Action != nil {
		out = append(out, varsIn(st.Action.Config)...)
	}
	return append(out, condVars(st.Condition)...)
}

func checkVar(v string, avail map[string]bool) error {
	segs := strings.Split(v, ".")
	if !runtimeRoots[segs[0]] {
		return fmt.Errorf("variable {{%s}} inconnue (detail, steps, flow, run)", v)
	}
	if segs[0] == "steps" && (len(segs) < 2 || !avail[segs[1]]) {
		return fmt.Errorf("{{%s}} : l'étape visée doit s'exécuter avant", v)
	}
	return nil
}

func validateStep(st *Step, flows map[string]*Flow) error {
	switch st.OnError {
	case "", "stop", "continue":
	default:
		return fmt.Errorf("on_error %q invalide (stop, continue)", st.OnError)
	}
	man, ok := stepManifest(st.Type)
	if !ok {
		return fmt.Errorf("type d'étape %q inconnu", st.Type)
	}
	cfg := map[string]any{}
	for k, v := range st.Config {
		cfg[k] = v
	}
	if st.Type == StepCall {
		if in, ok := cfg["inputs"]; ok {
			if _, isMap := in.(map[string]any); !isMap {
				return fmt.Errorf("inputs doit être un objet")
			}
			delete(cfg, "inputs")
		}
	}
	if err := man.Validate(cfg); err != nil {
		return err
	}
	switch st.Type {
	case StepAction:
		if st.Action == nil || st.Action.Type == "" {
			return fmt.Errorf("action requise")
		}
		return validateAction(st.Action)
	case StepIf:
		if st.Condition == nil {
			return fmt.Errorf("condition requise")
		}
		return validateCond(st.Condition, 1)
	case StepCall:
		target := flows[cfgStr(st.Config, "flow_id")]
		if target == nil {
			return fmt.Errorf("playbook appelé introuvable")
		}
		if target.Trigger.Kind != TriggerManual {
			return fmt.Errorf("seul un flux à déclenchement manuel (playbook) peut être appelé")
		}
	}
	return nil
}

func validateAction(a *Node) error {
	mod, man, ok := actionRegistry.Lookup(a.Type)
	if !ok {
		return fmt.Errorf("action inconnue : %q", a.Type)
	}
	cfg := a.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	for _, f := range man.Fields {
		if f.Secret && cfg[f.Key] == modules.Masque {
			return fmt.Errorf("action %s : %s est masqué, saisissez la valeur du secret", a.Type, f.Key)
		}
	}
	if err := man.Validate(cfg); err != nil {
		return fmt.Errorf("action %s : %w", a.Type, err)
	}
	if mod.check != nil {
		if err := mod.check(cfg); err != nil {
			return fmt.Errorf("action %s : %w", a.Type, err)
		}
	}
	return nil
}

// checkCallCycles refuse un flux qui, par ses étapes « lancer un playbook », finit par s'appeler lui-même.
func checkCallCycles(f *Flow, flows map[string]*Flow) error {
	calls := func(fl *Flow) []string {
		var out []string
		walkSteps(fl.Steps, func(st *Step) {
			if st.Type == StepCall {
				out = append(out, cfgStr(st.Config, "flow_id"))
			}
		})
		return out
	}
	state := map[string]int{} // 1 = en cours, 2 = vérifié
	var visit func(id string, depth int) error
	visit = func(id string, depth int) error {
		if state[id] == 1 {
			return invalid("appel circulaire entre playbooks")
		}
		if state[id] == 2 {
			return nil
		}
		fl := flows[id]
		if id == f.ID || (f.ID == "" && fl == nil) {
			fl = f
		}
		if fl == nil {
			return nil
		}
		if depth > maxDepth {
			return invalid("chaîne d'appels trop longue (%d au plus)", maxDepth)
		}
		state[id] = 1
		for _, c := range calls(fl) {
			if err := visit(c, depth+1); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	return visit(f.ID, 0)
}
