// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package sources range les sources de découverte de l'Agent (Docker/Podman, Portainer,
// Kubernetes…) comme des modules du registre commun (internal/modules, ADR 0007). Une source
// déclare un manifeste — type, libellé, champs de configuration dont les secrets — et une
// fabrique ; l'Agent la construit, la démarre, lui transmet le jeton d'appairage et annonce ses
// runtimes à l'Admin sans rien savoir d'elle. Ajouter une source (Consul, Nomad, ECS…) = un
// fichier qui appelle Register depuis init().
//
// Autonomie (ADR 0006) : une source ne dépend que de la passerelle de son Agent, jamais de
// l'Admin. Elle se construit et se démarre depuis la seule configuration locale de l'Agent.
package sources

import (
	"context"
	"log/slog"
	"sort"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/edgeset"
	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/modules"
)

// Deps regroupe ce qu'une fabrique peut utiliser. Les composants partagés (client Docker, gestion
// des réseaux, ensemble de passerelles) sont créés par l'Agent, qui s'en sert aussi ailleurs.
type Deps struct {
	Cfg    *config.AgentConfig
	Log    *slog.Logger
	Docker *agentdocker.Client
	Net    *agentdocker.NetworkManager
	Edges  *edgeset.Set
}

// Settings retourne la configuration d'une source qui n'a pas de section dédiée dans
// AgentConfig (sources ajoutées après les trois intégrées) : `sources.<type>` dans agent.json.
func (d Deps) Settings(typ string) map[string]any { return d.Cfg.Sources[typ] }

// Instance est une source construite.
type Instance struct {
	// Type est l'identifiant du module (renseigné par Build).
	Type string
	// Impl est la découverte concrète, pour l'accès typé de l'Agent (ex. rescan Docker).
	Impl any
	// Start lance la découverte.
	Start func(ctx context.Context)
	// Blocking : Start boucle jusqu'à l'annulation du contexte et doit être lancée dans sa propre
	// goroutine. Sinon Start rend la main après le scan initial.
	Blocking bool
	// SetToken reçoit le jeton d'agent obtenu à l'appairage, après la construction. Nil : la
	// source n'a pas de jeton à recevoir.
	SetToken func(token string)
	// Reannounce republie tout l'état de la source à la passerelle courante : à chaque
	// (re)connexion, après une bascule vers un autre membre du groupe HA, ou sur demande de
	// l'Admin. Nil : la source renvoie déjà tout périodiquement ou n'a rien à republier.
	Reannounce func(ctx context.Context)
	// Runtimes sont les noms annoncés à l'Admin (« docker », « podman », « portainer »…).
	Runtimes []string
}

// Factory construit une source depuis la configuration de l'Agent. (nil, nil) : source
// désactivée ou non configurée — ce n'est pas une erreur.
type Factory func(d Deps) (*Instance, error)

// Registry range les modules de découverte.
type Registry = modules.Registry[Factory]

// NewRegistry crée un registre vide (les tests y enregistrent leurs propres sources).
func NewRegistry() *Registry { return modules.NewRegistry[Factory]() }

var builtin = NewRegistry()

// Register déclare une source dans le registre de l'Agent. À appeler depuis init().
func Register(m modules.Manifest, f Factory) { builtin.Register(m, f) }

// Manifests retourne les manifestes des sources, dans l'ordre de déclaration.
func Manifests() []modules.Manifest { return builtin.Manifests() }

// Build construit les sources de reg actives pour d, dans l'ordre de déclaration. Une fabrique en
// erreur est journalisée et ignorée : une source cassée n'empêche pas les autres de démarrer.
func Build(reg *Registry, d Deps) []*Instance {
	var out []*Instance
	for _, m := range reg.Manifests() {
		f, _, _ := reg.Lookup(m.Type)
		if settings, ok := d.Cfg.Sources[m.Type]; ok {
			if err := m.Validate(settings); err != nil {
				d.Log.Warn("découverte : configuration de la source invalide, source ignorée", "source", m.Type, "err", err)
				continue
			}
		}
		inst, err := f(d)
		if err != nil {
			d.Log.Warn("découverte : source indisponible", "source", m.Type, "err", err)
			continue
		}
		if inst == nil {
			continue
		}
		inst.Type = m.Type
		out = append(out, inst)
	}
	return out
}

// BuildBuiltin construit les sources du registre de l'Agent.
func BuildBuiltin(d Deps) []*Instance { return Build(builtin, d) }

// SecretKeys retourne les noms de champs secrets déclarés par les manifestes de reg : l'Agent ne
// remplace jamais un secret enregistré par une valeur vide ou masquée quand l'Admin lui envoie un
// correctif de configuration.
func SecretKeys(reg *Registry) []string {
	seen := map[string]bool{}
	for _, m := range reg.Manifests() {
		for _, f := range m.Fields {
			if f.Secret {
				seen[f.Key] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BuiltinSecretKeys est SecretKeys pour le registre de l'Agent.
func BuiltinSecretKeys() []string { return SecretKeys(builtin) }

// View retourne la configuration d'une source prête à être envoyée à l'Admin (heartbeat) : les
// champs du manifeste, secrets masqués. Une clé absente de la configuration est omise.
func View(m modules.Manifest, section map[string]any) map[string]any {
	out := make(map[string]any, len(m.Fields))
	for _, f := range m.Fields {
		v, ok := section[f.Key]
		if !ok {
			continue
		}
		if f.Secret {
			if s, isStr := v.(string); isStr && s == "" {
				out[f.Key] = ""
			} else {
				out[f.Key] = modules.Masque
			}
			continue
		}
		out[f.Key] = v
	}
	return out
}

// ManifestOf retourne le manifeste d'une source du registre de l'Agent.
func ManifestOf(typ string) (modules.Manifest, bool) {
	_, m, ok := builtin.Lookup(typ)
	return m, ok
}
