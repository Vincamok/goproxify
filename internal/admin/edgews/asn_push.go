// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"

	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// asnChunkSize : un morceau de la base ASN compacte (≈ 3 Mo en tout) reste très en dessous de la limite d'un message WebSocket.
const asnChunkSize = 512 << 10

// ASNSource retourne la base ASN compacte de l'Admin et sa version ; faux si elle n'est pas installée.
type ASNSource func(ctx context.Context) (data []byte, version string, ok bool)

// SetASNSource branche la base ASN de l'Admin : elle est annoncée aux passerelles à leur connexion et quand elle change.
func (m *Manager) SetASNSource(fn ASNSource) { m.asnSource = fn }

// OfferASN annonce la version de la base ASN à toutes les passerelles ; celles qui ne l'ont pas la réclament (asn_db_want).
// Rien n'est envoyé aux passerelles qui ont déjà cette version.
func (m *Manager) OfferASN(ctx context.Context) {
	for _, e := range m.allEntries() {
		e := e
		go m.offerASNTo(ctx, e)
	}
}

func (m *Manager) offerASNTo(ctx context.Context, e *edgeEntry) {
	if m.asnSource == nil {
		return
	}
	_, version, ok := m.asnSource(ctx)
	if !ok {
		return
	}
	if err := e.client.PushJSON(edgeWS.TypeASNOffer, edgeWS.ASNOfferPayload{Version: version}); err != nil {
		m.log.Warn("edgews/manager: offre ASN", "edge", e.nodeName, "err", err)
	}
}

// handleASNWant envoie la base ASN, en morceaux, à la passerelle qui la réclame.
func (m *Manager) handleASNWant(raw json.RawMessage) {
	var p edgeWS.ASNWantPayload
	if m.asnSource == nil || json.Unmarshal(raw, &p) != nil || p.NodeName == "" {
		return
	}
	var target *edgeEntry
	for _, e := range m.allEntries() {
		if e.nodeName == p.NodeName {
			target = e
			break
		}
	}
	if target == nil {
		return
	}
	go func() {
		data, version, ok := m.asnSource(context.Background())
		if !ok || version == p.Have {
			return
		}
		total := (len(data) + asnChunkSize - 1) / asnChunkSize
		for seq := 0; seq < total; seq++ {
			end := (seq + 1) * asnChunkSize
			if end > len(data) {
				end = len(data)
			}
			chunk := edgeWS.ASNChunkPayload{Version: version, Seq: seq, Total: total, Data: data[seq*asnChunkSize : end]}
			if err := target.client.PushJSON(edgeWS.TypePushASN, chunk); err != nil {
				m.log.Warn("edgews/manager: envoi de la base ASN", "edge", target.nodeName, "seq", seq, "err", err)
				return
			}
		}
		m.log.Info("edgews/manager: base ASN envoyée", "edge", target.nodeName, "version", version, "octets", len(data))
	}()
}
