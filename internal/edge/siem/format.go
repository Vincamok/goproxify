// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Record est une ligne de la base de logs à exporter.
type Record struct {
	Node string
	Kind string // « access » ou « system »
	Row  logstore.Row
}

// ID est l'identifiant stable de la ligne : le même à chaque livraison, de quoi dédoublonner côté SIEM.
func (r Record) ID() string { return r.Node + ":" + r.Kind + ":" + strconv.FormatInt(r.Row.ID, 10) }

const tsLayout = "2006-01-02T15:04:05.000000Z"

// sdNameOK : les noms d'éléments structurés de la RFC 5424 ne contiennent ni espace, ni « = », « ] », « " ».
const sdEnterprise = "gpx@32473"

func severity(level string) int {
	switch strings.ToLower(level) {
	case "error":
		return 3
	case "warn", "warning":
		return 4
	case "debug":
		return 7
	}
	return 6
}

// header nettoie une valeur d'en-tête RFC 5424 : ASCII imprimable sans espace, 255 caractères au plus, « - » si vide.
func header(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// sdValue échappe une valeur d'élément structuré (RFC 5424 §6.3.3).
func sdValue(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`, "\r", " ", "\n", " ").Replace(s)
	return s
}

// clean remplace les caractères de contrôle d'un message : une ligne de log ne doit pas casser le cadrage.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
}

// Syslog met la ligne au format RFC 5424, sans cadrage. facility : 0 à 23 (local0 = 16).
func Syslog(r Record, facility int) []byte {
	row := r.Row
	var sd strings.Builder
	sd.WriteString("[" + sdEnterprise + ` id="` + sdValue(r.ID()) + `"`)
	add := func(k, v string) {
		if v != "" {
			sd.WriteString(" " + k + `="` + sdValue(v) + `"`)
		}
	}
	add("component", row.Component)
	add("domain", row.Domain)
	add("method", row.Method)
	add("path", row.Path)
	if row.Status > 0 {
		add("status", strconv.Itoa(row.Status))
	}
	add("ip", row.IP)
	if r.Kind == "access" {
		add("latency_ms", strconv.FormatInt(row.LatencyMs, 10))
		add("bytes", strconv.FormatInt(row.Bytes, 10))
	}
	add("user_agent", row.UserAgent)
	add("referrer", row.Referrer)
	add("request_id", row.RequestID)
	add("waf", strings.Join(row.WAFMatches, ","))
	add("threat", row.ThreatSignal)
	add("tls_ja3", row.TLSJA3)
	add("tls_ja4", row.TLSJA4)
	sd.WriteString("]")
	msg := row.Message
	if r.Kind == "access" && msg == "" {
		msg = fmt.Sprintf("%s %s %d", row.Method, row.Path, row.Status)
	}
	pri := facility*8 + severity(row.Level)
	return []byte(fmt.Sprintf("<%d>1 %s %s goproxify - %s %s %s", pri, row.Ts.UTC().Format(tsLayout), header(r.Node, 255), r.Kind, sd.String(), clean(msg)))
}

// jsonRecord est la ligne exportée en JSON : les champs ont les noms de l'API de logs.
type jsonRecord struct {
	ID           string   `json:"id"`
	Node         string   `json:"node"`
	Kind         string   `json:"kind"`
	Ts           string   `json:"ts"`
	Level        string   `json:"level"`
	Component    string   `json:"component,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	Method       string   `json:"method,omitempty"`
	Path         string   `json:"path,omitempty"`
	Status       int      `json:"status,omitempty"`
	IP           string   `json:"ip,omitempty"`
	LatencyMs    int64    `json:"latency_ms,omitempty"`
	Bytes        int64    `json:"bytes,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	Referrer     string   `json:"referrer,omitempty"`
	RequestID    string   `json:"request_id,omitempty"`
	WAFMatches   []string `json:"waf_matches,omitempty"`
	ThreatSignal string   `json:"threat_signal,omitempty"`
	TLSJA3       string   `json:"tls_ja3,omitempty"`
	TLSJA4       string   `json:"tls_ja4,omitempty"`
	IPTruncated  bool     `json:"ip_truncated,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// JSONLine met la ligne en JSON sur une seule ligne, sans saut de ligne final.
func JSONLine(r Record) []byte {
	row := r.Row
	b, _ := json.Marshal(jsonRecord{
		ID: r.ID(), Node: r.Node, Kind: r.Kind, Ts: row.Ts.UTC().Format(tsLayout), Level: row.Level, Component: row.Component,
		Domain: row.Domain, Method: row.Method, Path: row.Path, Status: row.Status, IP: row.IP, LatencyMs: row.LatencyMs, Bytes: row.Bytes,
		UserAgent: row.UserAgent, Referrer: row.Referrer, RequestID: row.RequestID, WAFMatches: row.WAFMatches,
		ThreatSignal: row.ThreatSignal, TLSJA3: row.TLSJA3, TLSJA4: row.TLSJA4, IPTruncated: row.IPTruncated, Message: row.Message,
	})
	return b
}
