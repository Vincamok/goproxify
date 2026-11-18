// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestAgentEventAlert(t *testing.T) {
	for _, tc := range []struct {
		eventType string
		trigger   alerting.TriggerType
		severity  alerting.Severity
	}{
		{"scale_up", alerting.TriggerScaleEvent, alerting.SevInfo},
		{"scale_down", alerting.TriggerScaleEvent, alerting.SevInfo},
		{"health_escalation", alerting.TriggerHealthEscalation, alerting.SevWarning},
	} {
		ev := agentEventAlert("host-1", "c1", tc.eventType, "d")
		if ev == nil || ev.Trigger != tc.trigger || ev.Severity != tc.severity {
			t.Errorf("%s : %+v, attendu %s/%s", tc.eventType, ev, tc.trigger, tc.severity)
			continue
		}
		if ev.NodeName != "host-1" || ev.Component != "agent" || ev.Detail["container"] != "c1" || ev.Detail["event_type"] != tc.eventType {
			t.Errorf("%s : champs inattendus %+v", tc.eventType, ev)
		}
	}
	for _, other := range []string{"health_critical", "container_started", ""} {
		if ev := agentEventAlert("host-1", "c1", other, ""); ev != nil {
			t.Errorf("%q ne doit pas alerter : %+v", other, ev)
		}
	}
}

// Un événement d'Agent relayé par la passerelle est enregistré ET alerté, par le chemin réel (HandleEdgeMessage) : la
// route HTTP qui le faisait avant n'avait aucun client, les alertes ne partaient donc jamais.
func TestAgentEventOverWebSocketRaisesAlert(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	engine := alerting.New(db, slog.Default())
	t.Cleanup(engine.Stop)
	got := make(chan alerting.Event, 4)
	engine.Subscribe(func(ev alerting.Event) { got <- ev })

	m := NewManager("secret", db, slog.Default())
	m.SetAlertEngine(engine)

	send := func(eventType string) {
		payload, _ := json.Marshal(map[string]string{"node_name": "host-1", "container_id": "c1", "event_type": eventType, "detail": "d"})
		m.HandleEdgeMessage(edgeWS.Message{Type: edgeWS.TypeAgentEvent, Payload: payload})
	}
	send("container_started")
	send("scale_up")
	select {
	case ev := <-got:
		if ev.Trigger != alerting.TriggerScaleEvent || ev.NodeName != "host-1" {
			t.Fatalf("alerte inattendue : %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scale_up n'a produit aucune alerte")
	}
	select {
	case ev := <-got:
		t.Fatalf("container_started ne doit pas alerter : %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM node_events WHERE node_name='host-1'`).Scan(&n) //nolint:errcheck
	if n != 2 {
		t.Fatalf("2 événements enregistrés attendus, %d", n)
	}
}
