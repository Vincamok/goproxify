// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package pairing sépare ce que l'on remet aux Agents de ce que seules l'Admin et les passerelles détiennent.
//
// GPX_PAIRING_SECRET (le secret racine) signe le WebSocket Admin → passerelle : qui le possède se fait passer pour
// l'Admin auprès de toutes les passerelles. Les Agents tournent sur des machines d'application (accès au socket du
// runtime) : ils reçoivent une clé dérivée, qui suffit à s'appairer et à authentifier les appels de l'Admin et de la
// passerelle vers l'Agent, mais dont le secret racine ne se déduit pas.
package pairing

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
)

const agentKeyLabel = "goproxify/agent-pairing/v1:"

// AgentKey dérive la clé d'appairage des Agents du secret racine. Le calcul tient en une ligne de shell
// (`printf %s "goproxify/agent-pairing/v1:$GPX_PAIRING_SECRET" | sha256sum`) pour que Helm et docker-compose
// puissent le faire sans outil supplémentaire.
func AgentKey(root string) string {
	if root == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(agentKeyLabel + root))
	return hex.EncodeToString(sum[:])
}

// Equal compare à temps constant (deux chaînes vides ne sont jamais égales).
func Equal(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// AgentCredential est ce qu'un Agent présente : GPX_AGENT_PAIRING_KEY, ou à défaut GPX_PAIRING_SECRET (installations
// qui n'ont pas encore migré : l'Agent détient alors le secret racine).
func AgentCredential() (value string, legacyRoot bool) {
	if k := os.Getenv("GPX_AGENT_PAIRING_KEY"); k != "" {
		return k, false
	}
	return os.Getenv("GPX_PAIRING_SECRET"), true
}

// AgentAccepts : valeurs que l'Agent accepte en Bearer de la part de l'Admin ou de sa passerelle. Celles-ci envoient
// la clé dérivée ; une passerelle d'avant cette version envoie encore le secret racine.
func AgentAccepts(credential string) []string {
	return []string{credential, AgentKey(credential)}
}

// ServerAcceptsAgent indique si le secret présenté par un Agent est valide pour une passerelle ou un Admin qui
// détient root. viaRoot est vrai quand l'Agent a présenté le secret racine lui-même.
func ServerAcceptsAgent(root, presented string) (ok, viaRoot bool) {
	if Equal(AgentKey(root), presented) {
		return true, false
	}
	if os.Getenv("GPX_AGENT_PAIRING_ROOT") != "false" && Equal(root, presented) {
		return true, true
	}
	return false, false
}
