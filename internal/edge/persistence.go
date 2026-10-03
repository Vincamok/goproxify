// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/buildinfo"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/cluster"
	"github.com/vincamok/goproxify/internal/edge/ipprofiles"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	"github.com/vincamok/goproxify/internal/edge/raft"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// --- Cache & reconnexion -------------------------------------------------

// applyIPProfiles met à jour le store en mémoire et persiste sur le volume passerelle.
func (s *Server) applyIPProfiles(profiles []*router.IPProfile) {
	s.profileStore.Replace(profiles)
	if err := ipprofiles.Save(ipprofiles.Dir(), profiles); err != nil {
		s.log.Warn("edge: persistance profils IP échouée", "err", err)
		return
	}
	s.log.Debug("edge: profils IP persistés", "count", len(profiles), "dir", ipprofiles.Dir())
}

func (s *Server) loadIPProfilesFromDisk() {
	profiles, err := ipprofiles.Load(ipprofiles.Dir())
	if err != nil {
		s.log.Warn("edge: lecture profils IP disque échouée", "err", err)
		return
	}
	if profiles == nil {
		return
	}
	s.profileStore.Replace(profiles)
	s.log.Info("edge: profils IP chargés depuis le disque",
		"count", len(profiles),
		"dir", ipprofiles.Dir(),
	)
}

// applyBans persiste la liste Admin (source "admin") en DB et reconstruit le BanStore.
func (s *Server) applyBans(list []*router.RuntimeBan) {
	if s.bansDB != nil {
		// Remplacer tous les bans source "admin" en DB.
		if err := s.bansDB.DeleteBansBySource("admin"); err != nil {
			s.log.Warn("edge: suppression bans admin DB échouée", "err", err)
		}
		for _, b := range list {
			if b == nil || b.IP == "" {
				continue
			}
			src := b.Source
			if src == "" {
				src = "admin"
			}
			if err := s.bansDB.UpsertBan(b.ID, b.IP, "", b.Reason, src, b.ExpiresAt); err != nil {
				s.log.Warn("edge: persistance ban admin DB échouée", "err", err)
			}
		}
	}
	s.reloadBanStore()
	s.log.Debug("edge: bans admin appliqués", "count", len(list))
}

func (s *Server) loadBansFromDisk() {
	if s.bansDB == nil {
		return
	}
	s.reloadBanStore()
	s.log.Info("edge: bans chargés depuis la DB", "count", s.banStore.Len())
}

// threatConfigPath est la copie locale chiffrée de la configuration Sentinel poussée par l'Admin.
func threatConfigPath() string {
	if p := os.Getenv("GPX_THREAT_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/threat-config.gpx"
}

// applyThreatConfig persiste la configuration Sentinel reçue de l'Admin puis l'applique. La copie est
// écrite même si le moteur n'existe pas encore : il la relira à son démarrage.
func (s *Server) applyThreatConfig(cfg threat.Config) {
	if err := s.cache.SaveFile(threatConfigPath(), cfg); err != nil {
		s.log.Warn(threat.Name+": persistance config échouée", "err", err)
	}
	if s.threatEngine == nil {
		return
	}
	s.threatEngine.UpdateConfig(cfg)
	// UpdateConfig remplace la liste blanche : y remettre les entrées sentinel_whitelist des routes.
	s.refreshSentinelWhitelists()
}

// loadThreatConfigFromDisk rend Sentinel opérationnel sans l'Admin après un redémarrage.
func (s *Server) loadThreatConfigFromDisk() {
	var cfg threat.Config
	ok, err := s.cache.LoadFile(threatConfigPath(), &cfg)
	if err != nil {
		s.log.Warn(threat.Name+": config locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.threatEngine.UpdateConfig(cfg)
	s.refreshSentinelWhitelists()
	s.log.Info(threat.Name+": config chargée depuis le disque", "enabled", cfg.Enabled)
}

// settingsPath est la copie locale chiffrée des réglages runtime poussés par l'Admin
// (protection des IP des access logs, journalisation, tracing, URL publique).
func settingsPath() string {
	if p := os.Getenv("GPX_EDGE_SETTINGS_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/edge-settings.gpx"
}

// receivePushedSettings persiste puis applique des réglages reçus de l'Admin. Sans copie
// locale, une passerelle redémarrée pendant une coupure de l'Admin écrirait les IP complètes
// dans son access log malgré l'anonymisation demandée.
func (s *Server) receivePushedSettings(p pushedSettings) {
	s.pushedMu.Lock()
	s.pushed = s.pushed.merge(p)
	err := s.cache.SaveFile(settingsPath(), s.pushed)
	s.pushedMu.Unlock()
	if err != nil {
		s.log.Warn("settings: persistance des réglages Admin échouée", "err", err)
	}
	s.applyPushedSettings(p)
}

// loadPushedSettingsFromDisk réapplique au démarrage les derniers réglages reçus de l'Admin.
func (s *Server) loadPushedSettingsFromDisk() {
	var p pushedSettings
	ok, err := s.cache.LoadFile(settingsPath(), &p)
	if err != nil {
		s.log.Warn("settings: copie locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.pushedMu.Lock()
	s.pushed = p
	s.pushedMu.Unlock()
	s.applyPushedSettings(p)
	s.log.Info("settings: réglages Admin chargés depuis le disque")
}

func (s *Server) saveCache() {
	// Invalider immédiatement les chaînes dispatch ; le flush disque est debouncé.
	s.invalidateDispatchCache()
	s.saveCacheMu.Lock()
	defer s.saveCacheMu.Unlock()
	if s.saveCacheTimer != nil {
		s.saveCacheTimer.Stop()
	}
	s.saveCacheTimer = time.AfterFunc(500*time.Millisecond, s.saveCacheNow)
}

func (s *Server) saveCacheNow() {
	snap := &edgecache.Snapshot{
		SavedAt:       time.Now(),
		Routes:        s.table.All(),
		Certs:         s.certStore.AllPEMs(),
		Snippets:      s.snippetStore.All(),
		AuthProviders: s.providerStore.All(),
		ECHKeys:       s.ech.Keys(),
	}
	if err := s.cache.Save(snap); err != nil {
		s.log.Warn("edge: sauvegarde cache échouée", "err", err)
		return
	}
	s.log.Debug("edge: cache local sauvegardé",
		"routes", len(snap.Routes),
		"certs", len(snap.Certs),
	)
}

// bansDBPurgeLoop purge toutes les heures les bans expirés et l'historique > 30 jours.
func (s *Server) bansDBPurgeLoop(ctx context.Context) {
	if s.bansDB == nil {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.bansDB.PurgeExpiredBans()
			_ = s.bansDB.PurgeBanHistory(time.Now().AddDate(0, 0, -30))
			_ = s.bansDB.PurgeUnbans(time.Now().AddDate(0, 0, -30))
			_ = s.bansDB.PurgeProxyErrors(time.Now().Add(-48 * time.Hour))
		}
	}
}

func (s *Server) autosaveLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.saveCacheNow()
			if err := s.wafEngine.SaveSnapshot("/etc/goproxify/waf-behavior.json"); err != nil {
				s.log.Warn("waf: autosave snapshot échoué", "err", err)
			}
		}
	}
}

func (s *Server) applyClusterCommand(entry raft.LogEntry) {
	cmd, err := cluster.DecodeCommand(entry)
	if err != nil {
		s.log.Warn("cluster: commande invalide", "err", err)
		return
	}
	switch cmd.Type {
	case cluster.CmdPushRoutes:
		var payload cluster.RoutesPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode routes", "err", err)
			return
		}
		var routes []*router.Route
		for _, raw := range payload.Routes {
			var r router.Route
			if err := json.Unmarshal(raw, &r); err == nil {
				routes = append(routes, &r)
			}
		}
		s.table.Replace(routes) //nolint:errcheck
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
		s.log.Info("cluster: routes appliquées", "count", len(routes))

	case cluster.CmdPushCert:
		var payload cluster.CertPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode cert", "err", err)
			return
		}
		if err := s.certStore.StorePEM(payload.Name, payload.CertPEM, payload.KeyPEM); err != nil {
			s.log.Warn("cluster: store cert", "err", err)
			return
		}
		s.writeCertToDisk(payload.Name, payload.CertPEM, payload.KeyPEM)
		metrics.Edge.CertCount.Set(float64(s.certStore.Len()))
		metrics.UpdateCertExpiries(s.certStore.CertExpiries())
		s.log.Info("cluster: certificat appliqué", "name", payload.Name)
	}
}

// wsHeartbeatLoop envoie un heartbeat passerelle → Admin toutes les 30 s via WebSocket.
func (s *Server) wsHeartbeatLoop(ctx context.Context) {
	send := func() {
		var cpuPct, memPct float64
		if prev, err := telemetry.ReadCPUStat(); err == nil {
			time.Sleep(200 * time.Millisecond)
			if cur, err := telemetry.ReadCPUStat(); err == nil {
				cpuPct = telemetry.CPUUsagePct(prev, cur)
			}
		}
		if mem, err := telemetry.ReadMemStat(); err == nil {
			memPct = mem.UsagePct()
		}
		msg, _ := edgews.NewMessage(0, edgews.TypeEdgeHeartbeat, edgews.EdgeHeartbeatPayload{
			NodeName: s.cfg.Identity.NodeName,
			Role:     "edge",
			Version:  buildinfo.Edge,
			CPUPct:   cpuPct,
			MemPct:   memPct,

			ClusterPeers: s.cfg.Cluster.Peers,
		})
		s.wsHub.BroadcastToAdmins(msg)
	}

	send()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}


// sendPortalLive envoie à l'Admin l'instantané des connexions pontées en cours du portail.
func (s *Server) sendPortalLive() {
	if s.portal == nil {
		return
	}
	msg, err := edgews.NewMessage(0, edgews.TypePortalLive, map[string]any{
		"node_name": s.cfg.Identity.NodeName,
		"sessions":  s.portal.LiveSessions(),
	})
	if err != nil {
		return
	}
	s.wsHub.BroadcastToAdmins(msg)
}

// portalLiveLoop renvoie l'instantané toutes les 30 s pour qu'un Admin redémarré retrouve l'état.
func (s *Server) portalLiveLoop(ctx context.Context) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if s.portal != nil && len(s.portal.LiveSessions()) > 0 {
				s.sendPortalLive()
			}
		}
	}
}

// ocspLoop agrafe aux certificats une réponse OCSP obtenue auprès de l'AC (sans l'Admin).
func (s *Server) ocspLoop(ctx context.Context) {
	st := edgetls.NewOCSPStapler(s.certStore, s.log.Logger())
	st.OnUpdate = func(status map[string]edgetls.OCSPStatus) {
		for name, ss := range status {
			secs := time.Until(ss.NextUpdate).Seconds()
			if secs < 0 {
				secs = 0
			}
			metrics.OCSPStapleSeconds.WithLabelValues(name).Set(secs)
			revoked := 0.0
			if ss.Revoked {
				revoked = 1
			}
			metrics.OCSPRevoked.WithLabelValues(name).Set(revoked)
		}
	}
	st.Run(ctx)
}
