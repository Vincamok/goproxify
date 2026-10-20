// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func postAgentLogs(t *testing.T, s *Server, container string, lines map[time.Time]string, order []time.Time) int {
	t.Helper()
	type entry struct {
		T    time.Time `json:"t"`
		Line string    `json:"line"`
	}
	var entries []entry
	for _, ts := range order {
		entries = append(entries, entry{ts, lines[ts]})
	}
	body, _ := json.Marshal(map[string]any{"container_id": "id-" + container, "container_name": container, "entries": entries})
	rec := httptest.NewRecorder()
	s.handleAgentLogs(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/logs", strings.NewReader(string(body))))
	return rec.Code
}

func systemMessages(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.logStore.ReadAfter(logstore.KindSystem, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		if r.Component == "agent" {
			out = append(out, r.Domain+":"+r.Message)
		}
	}
	return out
}

// Les logs d'un conteneur sont gardés dans la base de la passerelle avant l'accusé de réception ; un lot renvoyé
// (accusé perdu) ou qui chevauche le précédent ne double aucune ligne.
func TestAgentLogsAreStoredAndResentBatchesAreNotDuplicated(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	base := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	ts := func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }
	lines := map[time.Time]string{ts(1): "un", ts(2): "deux", ts(3): "trois", ts(4): "quatre"}

	if code := postAgentLogs(t, s, "web", lines, []time.Time{ts(1), ts(2), ts(3)}); code != http.StatusNoContent {
		t.Fatalf("premier lot : %d", code)
	}
	// Le lot est sur disque dès la réponse : lisible sans attendre l'écriture par lots.
	if got := strings.Join(systemMessages(t, s), ","); got != "web:un,web:deux,web:trois" {
		t.Fatalf("après le premier lot : %s", got)
	}
	// Renvoi du même lot, puis lot qui chevauche.
	postAgentLogs(t, s, "web", lines, []time.Time{ts(1), ts(2), ts(3)})
	postAgentLogs(t, s, "web", lines, []time.Time{ts(3), ts(4)})
	if got := strings.Join(systemMessages(t, s), ","); got != "web:un,web:deux,web:trois,web:quatre" {
		t.Fatalf("après renvois : %s", got)
	}
}

func TestAgentLogsOfTwoContainersAreIndependent(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	lines := map[time.Time]string{at: "meme-heure"}
	postAgentLogs(t, s, "web", lines, []time.Time{at})
	postAgentLogs(t, s, "db", lines, []time.Time{at})
	if got := len(systemMessages(t, s)); got != 2 {
		t.Fatalf("%d lignes, attendu 2 (une par conteneur)", got)
	}
}

// Deux lignes de même horodatage dans un même lot sont toutes deux gardées.
func TestAgentLogsKeepLinesSharingATimestampInOneBatch(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	body := `{"container_id":"c","container_name":"web","entries":[{"t":"2026-10-21T10:00:00Z","line":"a"},{"t":"2026-10-21T10:00:00Z","line":"b"}]}`
	rec := httptest.NewRecorder()
	s.handleAgentLogs(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	if got := strings.Join(systemMessages(t, s), ","); got != "web:a,web:b" {
		t.Fatalf("lignes = %s", got)
	}
}

// Si la base de logs ne peut pas garder le lot, la passerelle ne l'acquitte pas : l'Agent le relira.
func TestAgentLogsAreNotAcknowledgedWhenTheyCannotBeStored(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	_ = s.logStore.Close()
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	code := postAgentLogs(t, s, "web", map[time.Time]string{at: "x"}, []time.Time{at})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, attendu 503", code)
	}
}

