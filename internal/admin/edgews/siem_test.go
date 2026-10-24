// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

func TestSIEMLateEvents(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	alerted := map[string]time.Time{}
	late := siem.DestinationStatus{ID: "d1", Name: "Splunk", LagSec: 90 * 60, AlertAfterMin: 60, LastError: "réponse 503"}

	// En retard au-delà du seuil : une alerte d'avertissement.
	evs := siemLateEvents("gw-a", []siem.DestinationStatus{late}, alerted, now)
	if len(evs) != 1 || evs[0].Trigger != alerting.TriggerSIEMExportLag || evs[0].Severity != alerting.SevWarning || evs[0].NodeName != "gw-a" {
		t.Fatalf("événements : %+v", evs)
	}
	if evs[0].Detail["destination"] != "Splunk" || evs[0].Detail["lag_min"] != int64(90) || evs[0].Detail["error"] != "réponse 503" {
		t.Errorf("détail : %v", evs[0].Detail)
	}

	// Pas de rafale : l'état suivant, 30 s plus tard, n'alerte pas.
	if evs := siemLateEvents("gw-a", []siem.DestinationStatus{late}, alerted, now.Add(30*time.Second)); len(evs) != 0 {
		t.Fatalf("alerte répétée : %+v", evs)
	}
	// Mais le rappel arrive après l'intervalle.
	if evs := siemLateEvents("gw-a", []siem.DestinationStatus{late}, alerted, now.Add(siemAlertEvery+time.Minute)); len(evs) != 1 {
		t.Fatalf("pas de rappel : %+v", evs)
	}

	// Revenu à l'heure : oublié, la panne suivante alerte aussitôt.
	ok := siem.DestinationStatus{ID: "d1", Name: "Splunk", LagSec: 5, AlertAfterMin: 60}
	if evs := siemLateEvents("gw-a", []siem.DestinationStatus{ok}, alerted, now.Add(8*time.Hour)); len(evs) != 0 || len(alerted) != 0 {
		t.Fatalf("destination à l'heure : %+v, %v", evs, alerted)
	}
	if evs := siemLateEvents("gw-a", []siem.DestinationStatus{late}, alerted, now.Add(9*time.Hour)); len(evs) != 1 {
		t.Fatalf("la panne suivante n'alerte pas : %+v", evs)
	}

	// Des lignes menacées par la purge : critique, même sous le seuil de retard.
	risk := siem.DestinationStatus{ID: "d2", Name: "Syslog", LagSec: 10, AlertAfterMin: 60, AtRisk: true}
	if evs := siemLateEvents("gw-b", []siem.DestinationStatus{risk}, alerted, now); len(evs) != 1 || evs[0].Severity != alerting.SevCritical {
		t.Fatalf("à risque : %+v", evs)
	}

	// Une destination retirée n'est plus suivie ; celles des autres passerelles restent.
	siemLateEvents("gw-a", nil, alerted, now)
	if _, ok := alerted["gw-a/d1"]; ok {
		t.Error("destination retirée toujours suivie")
	}
	if _, ok := alerted["gw-b/d2"]; !ok {
		t.Error("la destination d'une autre passerelle a été oubliée")
	}
}
