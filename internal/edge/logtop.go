// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Un classement exact demande jusqu'à trois lectures de la période (ADR 0012) : le délai est celui d'une lecture.
const logTopTimeout = 20 * time.Second

// handleLogTop : POST /internal/v1/logs/top — un regroupement des accès par champ. Les filtres sont ceux de la
// recherche, passés en paramètres ; la demande (champ, mode, K, seuil, valeurs) est le corps JSON.
func (s *Server) handleLogTop(w http.ResponseWriter, r *http.Request) {
	q, err := logQuery(logapi.ParamsFromValues(r.URL.Query()))
	var req logapi.TopRequest
	if err == nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		err = json.NewDecoder(r.Body).Decode(&req)
	}
	if err == nil && !logstore.TopDimension(req.Dim) {
		err = errors.New("champ inconnu")
	}
	mode := logstore.TopMode(req.Mode)
	if err == nil && mode != logstore.TopBest && mode != logstore.TopAbove && mode != logstore.TopExact {
		err = errors.New("mode inconnu")
	}
	if err == nil && (req.K < 0 || req.K > 10000 || len(req.Values) > logstore.MaxTopValues) {
		err = errors.New("demande trop grande")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.withLogGateFor(w, r, false, logTopTimeout, func(ctx context.Context) {
		res, err := s.logStore.Top(ctx, q, logstore.TopRequest{Dim: req.Dim, Mode: mode, K: req.K, Min: req.Min, Values: req.Values, WithIPs: req.WithIPs})
		if err != nil {
			s.log.Warn("logs: regroupement échoué", "err", err)
			http.Error(w, "regroupement impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.TopResponse{Items: make([]logapi.TopItem, len(res.Items)), Complete: res.Complete, Partial: res.Partial}
		for i, it := range res.Items {
			out.Items[i] = logapi.TopItem{Value: it.Value, Requests: it.Requests, Errors: it.Errors, Bytes: it.Bytes,
				LatencySum: it.LatencySum, Flagged: it.Flagged, Blocked: it.Blocked, Ok: it.Ok, Bots: it.Bots, FirstSeen: it.FirstSeen, LastSeen: it.LastSeen, Truncated: it.Truncated, JA3: it.JA3, IPs: it.IPs}
		}
		writeJSON(w, out)
	})
}

// handleLogUniqueIPs : GET /internal/v1/logs/unique-ips — l'ensemble des IP des accès, résumé pour être fusionné.
func (s *Server) handleLogUniqueIPs(w http.ResponseWriter, r *http.Request) {
	q, err := logQuery(logapi.ParamsFromValues(r.URL.Query()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.withLogGateFor(w, r, false, logTopTimeout, func(ctx context.Context) {
		sum, partial, err := s.logStore.UniqueIPs(ctx, q)
		if err != nil {
			s.log.Warn("logs: IP distinctes échouées", "err", err)
			http.Error(w, "calcul impossible", http.StatusInternalServerError)
			return
		}
		writeJSON(w, logapi.UniqueIPsResponse{IPs: sum, Partial: partial})
	})
}
