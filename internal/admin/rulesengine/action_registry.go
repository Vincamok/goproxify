// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// ActionRun exécute une action. Elle reçoit le moteur (accès aux dépendances) et le contexte de la règle
// déclenchée.
type ActionRun func(e *Engine, ctx context.Context, ac ActionContext) error

// ActionCheck vérifie les valeurs d'une action déjà validée par son manifeste.
type ActionCheck func(cfg map[string]any) error

type actionModule struct {
	run   ActionRun
	check ActionCheck
}

// actionRegistry range les actions du moteur de règles (modules de la famille « Action », ADR 0007).
// Le manifeste décrit les champs de l'action ; l'API (types d'action, validation d'une règle, d'une
// planification) en découle au lieu d'une liste écrite à la main.
var actionRegistry = modules.NewRegistry[actionModule]()

// RegisterAction déclare une action.
//
// Les actions n'ont pas encore de gestion des secrets : une règle est relue par de nombreux endroits (liste,
// versions, historique, export, MCP) qui renverraient le secret en clair. Un manifeste qui déclare un champ
// secret est donc refusé au démarrage ; la gestion des secrets doit d'abord être ajoutée à ces sorties.
func RegisterAction(m modules.Manifest, run ActionRun, check ActionCheck) {
	for _, f := range m.Fields {
		if f.Secret {
			panic(fmt.Sprintf("rulesengine: l'action %q déclare le champ secret %q : non pris en charge", m.Type, f.Key))
		}
	}
	actionRegistry.Register(m, actionModule{run: run, check: check})
}

// ActionManifests retourne les manifestes des actions, dans l'ordre d'affichage.
func ActionManifests() []modules.Manifest { return actionRegistry.Manifests() }

// EdgeActionTypes retourne les types d'action que les passerelles savent exécuter (attribut « edge »).
// Seules les règles qui les utilisent leur sont poussées : une action de l'Admin (webhook, sauvegarde,
// playbook) n'a aucune raison de voyager vers une passerelle.
func EdgeActionTypes() map[string]bool {
	out := map[string]bool{}
	for _, m := range actionRegistry.Manifests() {
		if edge, _ := m.Attrs["edge"].(bool); edge {
			out[m.Type] = true
		}
	}
	return out
}

// Validate vérifie une action : type connu, champs requis, valeurs cohérentes.
func (a Action) Validate() error {
	mod, man, ok := actionRegistry.Lookup(string(a.Type))
	if !ok {
		return fmt.Errorf("type d'action inconnu : %q", a.Type)
	}
	b, _ := json.Marshal(a)
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	delete(cfg, "type")
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

func str(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return strings.TrimSpace(s)
}

// checkDuration vérifie qu'une durée facultative est lisible et strictement positive. Une durée illisible
// était ignorée à l'exécution : un ban voulu pour une heure devenait permanent.
func checkDuration(cfg map[string]any, key string) error {
	v := str(cfg, key)
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fmt.Errorf("%s : %q n'est pas une durée valide (ex. 30m, 24h)", key, v)
	}
	return nil
}

func fld(key, label, kind string, required bool) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: kind, Required: required}
}

func init() {
	edge := map[string]any{"edge": true}
	RegisterAction(modules.Manifest{Type: string(ActionDisableProxy), Label: "Désactiver le proxy", Attrs: edge,
		Fields: []modules.Field{fld("proxy_id", "Proxy (vide = celui de la condition)", modules.KindText, false)}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execDisableProxy(ctx, ac) }, nil)

	RegisterAction(modules.Manifest{Type: string(ActionBanIP), Label: "Bannir l'IP", Attrs: edge,
		Fields: []modules.Field{
			fld("ban_reason", "Motif", modules.KindText, false),
			fld("ban_duration", "Durée (vide = permanent)", modules.KindText, false),
		}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execBanIP(ctx, ac) },
		func(cfg map[string]any) error { return checkDuration(cfg, "ban_duration") })

	RegisterAction(modules.Manifest{Type: string(ActionNotify), Label: "Notifier", Attrs: edge,
		Fields: []modules.Field{
			fld("notify_severity", "Gravité (info, warning, critical)", modules.KindText, false),
			fld("notify_message", "Message", modules.KindText, false),
		}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { e.execNotify(ac); return nil },
		func(cfg map[string]any) error {
			switch str(cfg, "notify_severity") {
			case "", "info", "warning", "critical":
				return nil
			}
			return fmt.Errorf("notify_severity : %q invalide (info, warning, critical)", str(cfg, "notify_severity"))
		})

	RegisterAction(modules.Manifest{Type: string(ActionEnableStrict), Label: "Mode strict Fail2Ban (temporaire)", Attrs: edge,
		Fields: []modules.Field{fld("strict_duration", "Durée (défaut 30m)", modules.KindText, false)}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execEnableStrict(ctx, ac) },
		func(cfg map[string]any) error { return checkDuration(cfg, "strict_duration") })

	RegisterAction(modules.Manifest{Type: string(ActionWebhookCall), Label: "Appeler un webhook",
		Fields: []modules.Field{fld("webhook_url", "URL du webhook", modules.KindText, true)}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execWebhookCall(ctx, ac) },
		func(cfg map[string]any) error {
			u, err := url.Parse(str(cfg, "webhook_url"))
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("webhook_url : %q n'est pas une URL http(s)", str(cfg, "webhook_url"))
			}
			return nil
		})

	RegisterAction(modules.Manifest{Type: string(ActionRunBackup), Label: "Déclencher une sauvegarde",
		Fields: []modules.Field{fld("backup_retention", "Rétention (0 = pas de purge)", modules.KindNumber, false)}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execRunBackup(ctx, ac) },
		func(cfg map[string]any) error {
			if n, ok := cfg["backup_retention"].(float64); ok && n < 0 {
				return fmt.Errorf("backup_retention : %v négatif", n)
			}
			return nil
		})

	RegisterAction(modules.Manifest{Type: string(ActionRunPlaybook), Label: "Enchaîner un playbook",
		Fields: []modules.Field{fld("playbook_id", "Playbook", modules.KindText, true)}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execRunPlaybook(ctx, ac) }, nil)
}

// ValidateActionJSON valide une action sérialisée (import, MCP, planification).
func ValidateActionJSON(raw []byte) error {
	var a Action
	if err := json.Unmarshal(raw, &a); err != nil {
		return fmt.Errorf("action illisible : %w", err)
	}
	return a.Validate()
}
