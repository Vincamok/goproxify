// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

const ephorSimTimeout = 60 * time.Second

// handleEphorSimulate : POST /internal/v1/ephor/simulate — rejoue les accès récents de la passerelle contre deux
// configurations Ephor. La passerelle a le moteur et les lignes : l'Admin n'a rien à lui lire, il compare les rapports.
// Les agents utilisateur sont connus ici, les règles correspondantes sont donc évaluées.
func (s *Server) handleEphorSimulate(w http.ResponseWriter, r *http.Request) {
	var req logapi.EphorSimRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hours <= 0 || req.Hours > 24*7 {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	var current, candidate threat.Config
	if json.Unmarshal(req.Current, &current) != nil || json.Unmarshal(req.Candidate, &candidate) != nil {
		http.Error(w, "configuration illisible", http.StatusBadRequest)
		return
	}
	s.withLogGateFor(w, r, true, ephorSimTimeout, func(ctx context.Context) {
		events, skipped, truncated, partial, err := s.simEvents(ctx, time.Now().Add(-time.Duration(req.Hours)*time.Hour), req.Domain)
		if err != nil {
			s.log.Warn("ephor: lecture des accès pour la simulation échouée", "err", err)
			http.Error(w, "simulation impossible", http.StatusInternalServerError)
			return
		}
		writeJSON(w, logapi.EphorSimResponse{
			Current: threat.Simulate(current, events), Candidate: threat.Simulate(candidate, events),
			Events: len(events), Skipped: skipped, Truncated: truncated, Partial: partial,
		})
	})
}

// handleEphorReferences : GET /internal/v1/ephor/references — ce que la passerelle a appris, pour l'afficher à l'administrateur.
func (s *Server) handleEphorReferences(w http.ResponseWriter, r *http.Request) {
	out := logapi.EphorReferencesResponse{References: []behavior.RefInfo{}, TLSTable: behavior.TLSTableVersion}
	if s.behavior != nil {
		out.References = s.behavior.References()
		out.Profiles = s.behavior.Len()
	}
	if db := s.asnDB.Load(); db != nil {
		out.ASN.Version = db.Version()
		out.ASN.V4Ranges, out.ASN.V6Ranges = db.Len()
	}
	writeJSON(w, out)
}

// simEvents lit les accès depuis since, les plus récents d'abord, jusqu'à logapi.SimMaxEvents.
func (s *Server) simEvents(ctx context.Context, since time.Time, domain string) (events []threat.SimEvent, skipped int, truncated, partial bool, err error) {
	q := logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Domain: domain, From: since, Limit: 20000}
	for {
		page, err := s.logStore.Search(ctx, q)
		if err != nil {
			return nil, 0, false, false, err
		}
		partial = partial || page.Partial
		for _, row := range page.Rows {
			if row.Status <= 0 {
				continue
			}
			if _, perr := netip.ParseAddr(row.IP); perr != nil || row.IPTruncated {
				skipped++
				continue
			}
			if len(events) >= logapi.SimMaxEvents {
				return events, skipped, true, partial, nil
			}
			events = append(events, threat.SimEvent{Time: row.Ts, IP: row.IP, UA: row.UserAgent, Path: row.Path, Status: row.Status,
				Method: row.Method, TLS: row.TLSJA4, Route: row.Domain})
		}
		if !page.HasMore {
			return events, skipped, false, partial, nil
		}
		q.After = page.Next
	}
}

// handleEphorCalibrate : POST /internal/v1/ephor/calibrate — rejoue les accès récents de la passerelle avec une grille de réglages des
// valeurs de départ de l'ADR 0020 (référence saisonnière, énumération, empreintes TLS) et rend ce que chacun aurait signalé.
func (s *Server) handleEphorCalibrate(w http.ResponseWriter, r *http.Request) {
	var req logapi.EphorCalibrateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hours <= 0 || req.Hours > 24*7 || req.MinHours < 0 || req.MinHours > 168 {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	s.withLogGateFor(w, r, true, ephorSimTimeout, func(ctx context.Context) {
		events, skipped, truncated, partial, err := s.simEvents(ctx, time.Now().Add(-time.Duration(req.Hours)*time.Hour), req.Domain)
		if err != nil {
			s.log.Warn("ephor: lecture des accès pour le calibrage échouée", "err", err)
			http.Error(w, "calibrage impossible", http.StatusInternalServerError)
			return
		}
		rep := threat.Calibrate(events, threat.CalibrateOptions{
			MinHours: req.MinHours, WindowHours: float64(req.Hours), EnumShape: surface.EnumShape,
			EnumWindow: time.Duration(req.EnumWindowSeconds) * time.Second,
		})
		writeJSON(w, logapi.EphorCalibrateResponse{Report: rep, Skipped: skipped, Truncated: truncated, Partial: partial})
	})
}
