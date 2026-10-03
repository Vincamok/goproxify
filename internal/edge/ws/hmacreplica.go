// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"nhooyr.io/websocket"
)

var errNoHMACReplicaKey = errors.New("hmac: clé de groupe absente")

// La clé dérive de la clé du groupe HA avec son propre préfixe : une clé de réplication du portail
// ne déchiffre pas les HMAC des Agents, et inversement.
func hmacReplicaKey(haKey string) [32]byte {
	return sha256.Sum256([]byte("gpx-agent-hmac-replica|" + haKey))
}

// SealHMACReplica chiffre l'état des HMAC d'Agents avec la clé du groupe HA.
func SealHMACReplica(r HMACReplica, haKey string) ([]byte, error) {
	if haKey == "" {
		return nil, errNoHMACReplicaKey
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	key := hmacReplicaKey(haKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// OpenHMACReplica déchiffre un état reçu d'un pair ; échoue si la clé du groupe diffère.
func OpenHMACReplica(data []byte, haKey string) (HMACReplica, error) {
	var r HMACReplica
	if haKey == "" {
		return r, errNoHMACReplicaKey
	}
	key := hmacReplicaKey(haKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return r, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return r, err
	}
	if len(data) < gcm.NonceSize() {
		return r, errors.New("hmac: état trop court")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(plain, &r)
	return r, err
}

// HMACStore donne accès au magasin des HMAC d'Agents (réplication entre passerelles d'un groupe HA).
func (h *Hub) HMACStore() *AgentHMACStore { return h.hmacStore }

// DisconnectAgents ferme la connexion d'Agents dont le HMAC a été retiré par un pair du groupe. Le
// magasin n'est pas touché : la suppression y est déjà.
func (h *Hub) DisconnectAgents(ids []string) {
	for _, id := range ids {
		h.mu.Lock()
		ac, key := h.findAgentLocked(id)
		if ac != nil {
			delete(h.agentConns, key)
		}
		h.mu.Unlock()
		if ac == nil {
			continue
		}
		ac.mu.Lock()
		conn := ac.conn
		ac.mu.Unlock()
		if conn != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "agent révoqué")
		}
		h.log.Info("ws/agent: Agent révoqué par un pair du groupe — connexion fermée", "agent", id)
	}
}
