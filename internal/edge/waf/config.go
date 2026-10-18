// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

// EngineConfig est la configuration du WAF comme moteur de sécurité de la passerelle. Le réglage fin
// (mode, seuils, règles) reste porté par chaque route ; ici, un interrupteur maître.
type EngineConfig struct {
	// Enabled : faux coupe le WAF pour toutes les routes de la passerelle, sans toucher à leur réglage.
	Enabled bool `json:"enabled"`
}

// DefaultEngineConfig est la configuration d'une passerelle qui n'en a reçu aucune : le WAF est actif et
// chaque route décide de s'en servir.
func DefaultEngineConfig() EngineConfig { return EngineConfig{Enabled: true} }
