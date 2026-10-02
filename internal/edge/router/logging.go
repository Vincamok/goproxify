// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import "encoding/json"

// UnmarshalJSON applique le défaut documenté access_log=true quand la clé est absente
// (un bloc logging ne portant que level/format ne doit pas couper le log d'accès).
func (c *RouteLoggingConfig) UnmarshalJSON(data []byte) error {
	type plain RouteLoggingConfig
	aux := plain{AccessLog: true}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*c = RouteLoggingConfig(aux)
	return nil
}
