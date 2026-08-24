// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Load charge la configuration d'un composant depuis un fichier JSON,
// puis surcharge les valeurs avec les variables d'environnement préfixées GPX_.
//
// Priorité (de la plus forte à la plus faible) :
//  1. Variables d'environnement  GPX_<SECTION>_<KEY>=valeur
//  2. Fichier JSON               (chemin passé en argument)
//  3. Valeurs par défaut         (définies dans cette fonction)
//
// Exemples de surcharge par variable d'environnement :
//
//	GPX_APP_ENVIRONMENT=production
//	GPX_SERVER_API_PORT=9443
//	GPX_SECURITY_JWT_SECRET=mon_secret_prod
//	GPX_CONTROL_PLANE_AUTH_TOKEN=gpx_core_abc123
// Load charge la configuration depuis un fichier JSON.
//
// Comportement selon l'état du fichier :
//   - Fichier absent     → erreur (appeler Bootstrap*() avant Load)
//   - Fichier existant   → JSON seul fait foi ; les variables d'environnement
//     GPX_* ne surchargent PAS les valeurs déjà présentes dans le JSON.
//     Seules les clés absentes du JSON peuvent être alimentées par env var.
//     Exception : GPX_PAIRING_SECRET est toujours lu via os.Getenv() directement
//     dans le code, jamais via Viper, car il est partagé entre services.
//
// Pour les utilisateurs avancés qui souhaitent surcharger une valeur du JSON
// sans éditer le fichier : supprimer la clé du JSON, la valeur sera alors
// lue depuis la variable d'environnement correspondante.
func Load[T AdminConfig | CoreConfig | AgentConfig | LandingConfig](configPath string) (*T, error) {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("json")

	v.SetDefault("geoip.auto_download", true)
	v.SetDefault("geoip.db_path", "/etc/goproxify/geoip/GeoLite2-Country.mmdb")
	v.SetDefault("geoip.db_url", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("lecture config %q : %w", configPath, err)
	}

	// Les env vars ne surchargent que les clés absentes du JSON (pas de AutomaticEnv global).
	// On bind uniquement les clés qui peuvent légitimement manquer dans le JSON
	// pour permettre à l'utilisateur avancé de les passer en env var.
	bindIfMissing(v, "cluster.peers") // GPX_CLUSTER_PEERS : liste complexe, non générée par bootstrap

	var cfg T
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q : %w", configPath, err)
	}

	return &cfg, nil
}

// bindIfMissing lie une variable d'env uniquement si la clé est absente du JSON chargé.
func bindIfMissing(v *viper.Viper, key string) {
	if !v.IsSet(key) {
		envKey := "GPX_" + strings.ToUpper(strings.NewReplacer(".", "_").Replace(key))
		_ = v.BindEnv(key, envKey)
	}
}

// LoadAdmin charge admin.json → AdminConfig.
func LoadAdmin(path string) (*AdminConfig, error) {
	return Load[AdminConfig](path)
}

// LoadCore charge core.json → CoreConfig.
func LoadCore(path string) (*CoreConfig, error) {
	cfg, err := Load[CoreConfig](path)
	if err != nil {
		return nil, err
	}
	applyClusterPeersEnv(cfg)
	return cfg, nil
}

// applyClusterPeersEnv parse GPX_CLUSTER_PEERS si la map Peers est vide.
// Formats acceptés (séparés par virgule) :
//   - id=http://host:8002
//   - id:8002  → http://id:8002
//   - host:8002 → clé = host
func applyClusterPeersEnv(cfg *CoreConfig) {
	if cfg == nil || len(cfg.Cluster.Peers) > 0 {
		return
	}
	raw := strings.TrimSpace(os.Getenv("GPX_CLUSTER_PEERS"))
	if raw == "" {
		return
	}
	peers := parseClusterPeersCSV(raw)
	if len(peers) > 0 {
		cfg.Cluster.Peers = peers
	}
}

func parseClusterPeersCSV(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, url := "", ""
		if i := strings.IndexByte(part, '='); i > 0 {
			id = strings.TrimSpace(part[:i])
			url = strings.TrimSpace(part[i+1:])
		} else if i := strings.LastIndexByte(part, ':'); i > 0 {
			host := strings.TrimSpace(part[:i])
			port := strings.TrimSpace(part[i+1:])
			host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
			id = host
			url = "http://" + host + ":" + port
		} else {
			continue
		}
		if id == "" || url == "" {
			continue
		}
		if !strings.Contains(url, "://") {
			url = "http://" + url
		}
		out[id] = url
	}
	return out
}

// LoadAgent charge agent.json → AgentConfig.
func LoadAgent(path string) (*AgentConfig, error) {
	return Load[AgentConfig](path)
}

// LoadLanding charge landing/config.json → LandingConfig.
func LoadLanding(path string) (*LandingConfig, error) {
	return Load[LandingConfig](path)
}
