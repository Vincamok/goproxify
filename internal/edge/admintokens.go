// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"errors"

	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
)

// adminWSTokenName : nom sous lequel la passerelle retient le jeton que l'Admin lui pousse (TypeAdminToken). Un Admin
// remplacé laisse le sien : il reste valable tant que personne ne le retire.
const adminWSTokenName = "admin-ws"

// revokeStaleAdminTokens révoque tous les jetons poussés par un Admin sauf celui que l'Admin actuel présente (ADR 0015,
// éviction d'urgence). Le jeton à garder est enregistré d'abord : l'appelant ne se coupe jamais l'accès. Les jetons
// d'amorçage de la configuration (`admin-<nœud>`) ne sont pas concernés.
func (s *Server) revokeStaleAdminTokens(keep string) error {
	if s.tokenStore == nil {
		return errors.New("magasin de jetons indisponible")
	}
	if keep == "" {
		return errors.New("jeton Admin à garder requis")
	}
	if err := s.tokenStore.EnsureToken(adminWSTokenName, keep, edgetokens.RoleAdmin); err != nil {
		return err
	}
	n, err := s.tokenStore.RevokeNamedExcept(adminWSTokenName, keep)
	if err != nil {
		return err
	}
	s.adminTokenMu.Lock()
	s.adminToken = keep
	s.adminTokenMu.Unlock()
	s.log.Warn("admin: anciens jetons Admin révoqués", "revoques", n)
	return nil
}
