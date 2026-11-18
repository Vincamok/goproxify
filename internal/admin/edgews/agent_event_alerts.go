// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"strings"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

// agentEventAlert rend l'alerte d'un événement d'Agent relayé par une passerelle : montée ou descente d'échelle
// (scale_up, scale_down…) et escalade de santé d'un conteneur. Les autres types ne produisent pas d'alerte.
func agentEventAlert(nodeName, containerID, eventType, detail string) *alerting.Event {
	ev := alerting.Event{
		NodeName:  nodeName,
		Component: "agent",
		Detail:    map[string]any{"event_type": eventType, "detail": detail, "container": containerID},
	}
	switch {
	case strings.HasPrefix(eventType, "scale_"):
		ev.Trigger, ev.Severity = alerting.TriggerScaleEvent, alerting.SevInfo
	case eventType == "health_escalation":
		ev.Trigger, ev.Severity = alerting.TriggerHealthEscalation, alerting.SevWarning
	default:
		return nil
	}
	return &ev
}
