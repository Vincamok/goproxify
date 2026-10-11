// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package automation exécute les flux d'automatisation de l'Admin (ADR 0009). Un flux est un
// déclencheur (condition, événement, horaire ou manuel), un garde-fou (délai minimum, concurrence) et une
// suite d'étapes (action, attente, si/sinon, approbation, appel d'un autre flux, arrêt). Règles,
// planifications et playbooks sont des flux qui ne diffèrent que par leur déclencheur.
//
// Déclencheurs, conditions, actions et types d'étape sont des modules (ADR 0007) : leur manifeste décrit
// leurs champs, et le catalogue de l'API en découle.
package automation

import (
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// TriggerKind est le type de déclencheur d'un flux ; il décide de l'onglet où le flux apparaît.
type TriggerKind string

const (
	TriggerCondition TriggerKind = "condition" // condition évaluée périodiquement (Règles)
	TriggerEvent     TriggerKind = "event"     // événement du moteur d'alertes (Règles)
	TriggerSchedule  TriggerKind = "schedule"  // expression cron (Planifications)
	TriggerManual    TriggerKind = "manual"    // lancé à la main ou par un autre flux (Playbooks)
)

// Types d'étape.
const (
	StepAction   = "action"
	StepWait     = "wait"
	StepIf       = "if"
	StepApproval = "approval"
	StepCall     = "call"
	StepStop     = "stop"
)

// Placement : où le flux est évalué.
const (
	PlacementAdmin = "admin"
	PlacementEdge  = "edge"
	PlacementAuto  = "auto"
)

// Flow est un flux d'automatisation.
type Flow struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Enabled     bool    `json:"enabled"`
	Trigger     Trigger `json:"trigger"`
	Guard       Guard   `json:"guard"`
	Steps       []Step  `json:"steps"`
	Origin      Origin  `json:"origin"`
	Version     int     `json:"version"`
	// Placement est calculé (lecture seule) : edge quand la passerelle sait exécuter le flux seule.
	Placement       string     `json:"placement,omitempty"`
	PlacementReason string     `json:"placement_reason,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CreatedBy       string     `json:"created_by,omitempty"`
	State           *FlowState `json:"state,omitempty"`
}

// FlowState est l'état d'exécution d'un flux (lecture seule, non versionné).
type FlowState struct {
	FireCount     int        `json:"fire_count"`
	LastFiredAt   *time.Time `json:"last_fired_at,omitempty"`
	LastRunID     string     `json:"last_run_id,omitempty"`
	LastRunStatus RunStatus  `json:"last_run_status,omitempty"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	Waiting       int        `json:"waiting"`
}

// Trigger décrit ce qui démarre un flux. Seul le sous-objet du type choisi est renseigné.
type Trigger struct {
	Kind        TriggerKind      `json:"kind"`
	Condition   *Cond            `json:"condition,omitempty"`
	IntervalSec int              `json:"interval_sec,omitempty"`
	Event       *EventTrigger    `json:"event,omitempty"`
	Schedule    *ScheduleTrigger `json:"schedule,omitempty"`
	Manual      *ManualTrigger   `json:"manual,omitempty"`
}

// Cond est une condition simple (Type + Config) ou un groupe : exactement un de All, Any, Not.
type Cond struct {
	All    []Cond         `json:"all,omitempty"`
	Any    []Cond         `json:"any,omitempty"`
	Not    *Cond          `json:"not,omitempty"`
	Type   string         `json:"type,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

// EventTrigger : un événement du moteur d'alertes, filtré par périmètre et par valeurs de détail.
type EventTrigger struct {
	Event       string            `json:"event"`
	Nodes       []string          `json:"nodes,omitempty"`
	DomainGlob  string            `json:"domain_glob,omitempty"`
	MinSeverity string            `json:"min_severity,omitempty"`
	Match       map[string]string `json:"match,omitempty"` // clé de détail → motif (filepath.Match)
}

// ScheduleTrigger : expression cron à 5 champs, à l'heure locale de l'Admin.
type ScheduleTrigger struct {
	Cron string `json:"cron"`
}

// ManualTrigger : paramètres saisis au lancement, disponibles en {{detail.<clé>}}.
type ManualTrigger struct {
	Inputs []modules.Field `json:"inputs,omitempty"`
}

// Guard filtre les déclenchements.
type Guard struct {
	CooldownSec int `json:"cooldown_sec,omitempty"`
	// CooldownKey : délai minimum par valeur (ex. « {{detail.ip}} ») plutôt que pour tout le flux.
	CooldownKey   string `json:"cooldown_key,omitempty"`
	MaxConcurrent int    `json:"max_concurrent,omitempty"` // exécutions simultanées (0 = 1)
	Placement     string `json:"placement,omitempty"`      // auto (défaut) | admin
}

// Step est une étape. Les champs utilisés dépendent du type.
type Step struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name,omitempty"`
	Config    map[string]any `json:"config,omitempty"`
	Action    *Node          `json:"action,omitempty"`
	Condition *Cond          `json:"condition,omitempty"`
	Then      []Step         `json:"then,omitempty"`
	Else      []Step         `json:"else,omitempty"`
	OnError   string         `json:"on_error,omitempty"` // stop (défaut) | continue
}

// Node est une brique configurée (action).
type Node struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config,omitempty"`
}

// Origine d'un flux.
const (
	OriginManual   = "manual"
	OriginTemplate = "template"
)

// Origin : un flux construit dans l'éditeur, ou installé depuis un modèle (rééditable par ses paramètres).
type Origin struct {
	Kind            string         `json:"kind"`
	TemplateID      string         `json:"template_id,omitempty"`
	TemplateVersion int            `json:"template_version,omitempty"`
	Params          map[string]any `json:"params,omitempty"`
}

// RunStatus est l'état d'une exécution.
type RunStatus string

const (
	RunRunning         RunStatus = "running"
	RunWaiting         RunStatus = "waiting"          // étape « attendre »
	RunWaitingApproval RunStatus = "waiting_approval" // étape « approbation »
	RunWaitingChild    RunStatus = "waiting_child"    // étape « appeler un flux » qui attend la fin de l'appelé
	RunCompleted       RunStatus = "completed"
	RunStopped         RunStatus = "stopped" // arrêt voulu (étape « arrêter »)
	RunFailed          RunStatus = "failed"
	RunRejected        RunStatus = "rejected"    // approbation refusée
	RunSilenced        RunStatus = "silenced"    // déclenchement couvert par une mise en sourdine
	RunInterrupted     RunStatus = "interrupted" // l'Admin s'est arrêté pendant l'exécution
	RunCancelled       RunStatus = "cancelled"
)

// Finished indique un état terminal.
func (s RunStatus) Finished() bool {
	switch s {
	case RunRunning, RunWaiting, RunWaitingApproval, RunWaitingChild:
		return false
	}
	return true
}

// Run est une exécution d'un flux.
type Run struct {
	ID           string      `json:"id"`
	FlowID       string      `json:"flow_id"`
	FlowName     string      `json:"flow_name"`
	FlowVersion  int         `json:"flow_version"`
	Source       string      `json:"source"` // admin | edge:<nœud> | manual:<acteur> | call:<run>
	TriggerKind  TriggerKind `json:"trigger_kind"`
	Status       RunStatus   `json:"status"`
	Cursor       string      `json:"cursor,omitempty"`
	Context      RunContext  `json:"context"`
	ResumeAt     *time.Time  `json:"resume_at,omitempty"`
	ParentRunID  string      `json:"parent_run_id,omitempty"`
	ParentStepID string      `json:"parent_step_id,omitempty"`
	Depth        int         `json:"depth,omitempty"`
	Error        string      `json:"error,omitempty"`
	StartedAt    time.Time   `json:"started_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	FinishedAt   *time.Time  `json:"finished_at,omitempty"`
	Steps        []StepLog   `json:"steps,omitempty"`
	// Pending décrit l'approbation attendue (statut waiting_approval).
	Pending *PendingApproval `json:"pending,omitempty"`

	definition definition
}

// PendingApproval décrit l'étape d'approbation sur laquelle une exécution attend.
type PendingApproval struct {
	StepID  string `json:"step_id"`
	Message string `json:"message,omitempty"`
}

// RunContext porte les variables d'une exécution.
type RunContext struct {
	Detail map[string]any            `json:"detail"`
	Steps  map[string]map[string]any `json:"steps"`
	Chain  []string                  `json:"chain,omitempty"` // flux qui ont provoqué celui-ci (anti-boucle)
}

// StepLog journalise une étape exécutée (ou simulée).
type StepLog struct {
	StepID     string         `json:"step_id"`
	Type       string         `json:"type"`
	Status     string         `json:"status"` // done | failed | skipped | waiting | approved | rejected | simulated
	Detail     string         `json:"detail,omitempty"`
	Output     map[string]any `json:"output,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	Flow       string         `json:"flow,omitempty"` // flux appelé (simulation d'un appel)
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

// Silence suspend les déclenchements sur une fenêtre de temps. RuleIDs vise des flux et des règles de
// routage d'alertes (le moteur d'alertes lit la même table) ; vide, il couvre tout.
type Silence struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	RuleIDs   []string  `json:"rule_ids"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Active indique si le silence couvre l'instant t pour le flux flowID.
func (s Silence) Active(t time.Time, flowID string) bool {
	if t.Before(s.StartsAt) || t.After(s.EndsAt) {
		return false
	}
	if len(s.RuleIDs) == 0 {
		return true
	}
	for _, id := range s.RuleIDs {
		if id == flowID {
			return true
		}
	}
	return false
}

// definition est la partie versionnée et copiée dans chaque exécution.
type definition struct {
	Trigger Trigger `json:"trigger"`
	Guard   Guard   `json:"guard"`
	Steps   []Step  `json:"steps"`
}

func (f *Flow) definition() definition {
	return definition{Trigger: f.Trigger, Guard: f.Guard, Steps: f.Steps}
}

// walkSteps visite chaque étape, branches comprises, dans l'ordre du document.
func walkSteps(steps []Step, fn func(*Step)) {
	for i := range steps {
		fn(&steps[i])
		walkSteps(steps[i].Then, fn)
		walkSteps(steps[i].Else, fn)
	}
}
