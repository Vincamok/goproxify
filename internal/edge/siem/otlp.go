// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// OTLP/HTTP, encodage JSON (ExportLogsServiceRequest) : l'adresse de la destination est l'URL complète du collecteur,
// par exemple http://collector.example.com:4318/v1/logs. Les noms d'attributs suivent les conventions sémantiques d'OpenTelemetry
// quand elles existent ; les autres sont préfixés « goproxify. ».

type otlpValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"` // un entier 64 bits s'écrit en chaîne décimale (mapping JSON de protobuf)
	BoolValue   *bool   `json:"boolValue,omitempty"`
}

type otlpAttr struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 otlpValue  `json:"body"`
	Attributes           []otlpAttr `json:"attributes,omitempty"`
}

type otlpScopeLogs struct {
	Scope struct {
		Name string `json:"name"`
	} `json:"scope"`
	LogRecords []otlpRecord `json:"logRecords"`
}

type otlpResourceLogs struct {
	Resource struct {
		Attributes []otlpAttr `json:"attributes"`
	} `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

func strAttr(k, v string) otlpAttr { return otlpAttr{Key: k, Value: otlpValue{StringValue: &v}} }
func intAttr(k string, v int64) otlpAttr {
	s := strconv.FormatInt(v, 10)
	return otlpAttr{Key: k, Value: otlpValue{IntValue: &s}}
}
func boolAttr(k string, v bool) otlpAttr { return otlpAttr{Key: k, Value: otlpValue{BoolValue: &v}} }

// otlpSeverity rend le numéro de gravité OTLP d'un niveau (DEBUG 5, INFO 9, WARN 13, ERROR 17).
func otlpSeverity(level string) (int, string) {
	switch strings.ToLower(level) {
	case "error":
		return 17, "ERROR"
	case "warn", "warning":
		return 13, "WARN"
	case "debug":
		return 5, "DEBUG"
	}
	return 9, "INFO"
}

func otlpRecordOf(r Record) otlpRecord {
	row := r.Row
	sev, text := otlpSeverity(row.Level)
	body := row.Message
	if r.Kind == "access" && body == "" {
		body = fmt.Sprintf("%s %s %d", row.Method, row.Path, row.Status)
	}
	ts := strconv.FormatInt(row.Ts.UnixNano(), 10)
	attrs := []otlpAttr{strAttr("log.id", r.ID()), strAttr("goproxify.kind", r.Kind)}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, strAttr(k, v))
		}
	}
	add("goproxify.component", row.Component)
	add("server.address", row.Domain)
	add("http.request.method", row.Method)
	add("url.path", row.Path)
	if row.Status > 0 {
		attrs = append(attrs, intAttr("http.response.status_code", int64(row.Status)))
	}
	add("client.address", row.IP)
	if row.IPTruncated {
		attrs = append(attrs, boolAttr("goproxify.client.ip_truncated", true))
	}
	if r.Kind == "access" {
		attrs = append(attrs, intAttr("http.response.body.size", row.Bytes), intAttr("goproxify.latency_ms", row.LatencyMs))
	}
	add("user_agent.original", row.UserAgent)
	add("http.request.header.referer", row.Referrer)
	add("goproxify.request_id", row.RequestID)
	add("goproxify.waf_matches", strings.Join(row.WAFMatches, ","))
	add("goproxify.threat_signal", row.ThreatSignal)
	add("tls.client.ja3", row.TLSJA3)
	add("tls.client.ja4", row.TLSJA4)
	return otlpRecord{TimeUnixNano: ts, ObservedTimeUnixNano: ts, SeverityNumber: sev, SeverityText: text, Body: otlpValue{StringValue: &body}, Attributes: attrs}
}

// OTLPBody met un lot de lignes au format OTLP/HTTP JSON.
func OTLPBody(recs []Record) []byte {
	if len(recs) == 0 {
		return []byte(`{"resourceLogs":[]}`)
	}
	var rl otlpResourceLogs
	rl.Resource.Attributes = []otlpAttr{strAttr("service.name", "goproxify-edge"), strAttr("host.name", recs[0].Node)}
	var sl otlpScopeLogs
	sl.Scope.Name = "goproxify.logs"
	for _, r := range recs {
		sl.LogRecords = append(sl.LogRecords, otlpRecordOf(r))
	}
	rl.ScopeLogs = []otlpScopeLogs{sl}
	b, _ := json.Marshal(otlpRequest{ResourceLogs: []otlpResourceLogs{rl}})
	return b
}
