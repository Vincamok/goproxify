// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"context"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// Bundle est le certificat à déployer.
type Bundle struct {
	Domain    string
	CertPEM   string
	KeyPEM    string
	ExpiresAt time.Time
}

// Target déploie un certificat vers une destination. Deploy retourne ("ok"|"error", message) ; le
// message est conservé dans l'historique du déploiement.
type Target interface {
	Deploy(ctx context.Context, b Bundle) (status, message string)
}

// Deps regroupe ce qu'une fabrique de cible peut utiliser.
type Deps struct {
	Client *http.Client
}

// Factory construit une cible depuis sa configuration stockée. Une erreur est une configuration
// inutilisable ; son message devient celui de l'historique. La configuration peut être partielle :
// une cible créée avant la validation ne doit jamais empêcher le déploiement des autres.
type Factory func(cfg map[string]any, d Deps) (Target, error)

// registry range les types de cible de déploiement (modules de la famille « cibles », ADR 0007).
// Le manifeste d'un type décrit sa configuration (champs, secrets, requis) ; la validation à la
// création, le masquage des secrets dans l'API et le formulaire de l'Admin en découlent. Ajouter un
// type (Kubernetes Secret, AWS ACM, Synology…) = un fichier qui appelle Register depuis init().
// Le type « pull_token » n'en fait pas partie : c'est la cible qui vient chercher le certificat.
var registry = modules.NewRegistry[Factory]()

// Register déclare un type de cible. À appeler depuis init().
func Register(m modules.Manifest, f Factory) { registry.Register(m, f) }

// Manifests retourne les manifestes des types de cible, dans l'ordre de déclaration.
func Manifests() []modules.Manifest { return registry.Manifests() }

// ManifestOf retourne le manifeste d'un type de cible.
func ManifestOf(typ string) (modules.Manifest, bool) {
	_, m, ok := registry.Lookup(typ)
	return m, ok
}

// Types retourne les types de cible connus, triés.
func Types() []string { return registry.Types() }

func str(cfg map[string]any, k string) string {
	s, _ := cfg[k].(string)
	return s
}

// Les types fournis, dans l'ordre d'affichage. Un seul init() : l'ordre des init() de plusieurs
// fichiers dépend de leur nom, pas de l'intention.
func init() {
	registerWebhook()
	registerSSH()
}

// Learner est implémenté par une cible qui apprend une valeur pendant un déploiement et veut la
// conserver dans sa configuration (confiance à la première utilisation de la clé d'hôte SSH).
// Le Deployer n'écrit que les champs encore vides.
type Learner interface {
	Learned() map[string]any
}
