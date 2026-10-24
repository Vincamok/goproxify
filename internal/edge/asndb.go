// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/netip"
	"os"
	"sync"

	"github.com/vincamok/goproxify/internal/asncompact"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// La base IP → ASN sert à l'agrégat par ASN d'Ephor (ADR 0011) : plusieurs IP d'un même opérateur qui échouent chacune sous les
// seuils. L'Admin la possède et la pousse en morceaux ; la passerelle en garde une copie chiffrée et s'en sert seule (ADR 0006).
// Sans base, l'agrégat par ASN reste muet : rien d'autre ne s'arrête.

// asnPath est la copie locale chiffrée de la base ASN poussée par l'Admin.
func asnPath() string {
	if p := os.Getenv("GPX_ASN_DB_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/asn-db.gpx"
}

type asnFile struct {
	Version string `json:"version"`
	Data    []byte `json:"data"` // base compacte, gzip
}

// asnAssembly rassemble les morceaux d'une base en cours de réception.
type asnAssembly struct {
	mu      sync.Mutex
	version string
	total   int
	parts   map[int][]byte
	size    int
}

const maxASNBytes = 64 << 20

// lookupASN retourne l'ASN d'une adresse, 0 si la base manque ou ne la connaît pas.
func (s *Server) lookupASN(ip string) uint32 {
	db := s.asnDB.Load()
	if db == nil {
		return 0
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	return db.Lookup(a)
}

func (s *Server) asnVersion() string {
	if db := s.asnDB.Load(); db != nil {
		return db.Version()
	}
	return ""
}

func (s *Server) loadASNFromDisk() {
	var f asnFile
	ok, err := s.cache.LoadFile(asnPath(), &f)
	if err != nil {
		s.log.Warn(threat.Name+": base ASN locale illisible — l'agrégat par ASN attend l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	db, err := asncompact.Decode(f.Data)
	if err != nil {
		s.log.Warn(threat.Name+": base ASN locale invalide — l'agrégat par ASN attend l'Admin", "err", err)
		return
	}
	s.asnDB.Store(db)
	v4, v6 := db.Len()
	s.log.Info(threat.Name+": base ASN chargée depuis le disque", "version", db.Version(), "plages_ipv4", v4, "plages_ipv6", v6)
}

// handleASNOffer : l'Admin annonce la version qu'il a ; la passerelle la réclame si elle n'a pas la même.
func (s *Server) handleASNOffer(p edgews.ASNOfferPayload) {
	if p.Version == "" || p.Version == s.asnVersion() {
		return
	}
	if msg, err := edgews.NewMessage(0, edgews.TypeASNWant, edgews.ASNWantPayload{NodeName: s.cfg.Identity.NodeName, Have: s.asnVersion()}); err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}

// applyASNChunk reçoit un morceau de la base ; au dernier, elle est lue, installée et copiée sur le volume.
func (s *Server) applyASNChunk(c edgews.ASNChunkPayload) {
	if c.Version == "" || c.Total <= 0 || c.Total > 1024 || c.Seq < 0 || c.Seq >= c.Total {
		return
	}
	a := &s.asnAsm
	a.mu.Lock()
	if a.version != c.Version || a.total != c.Total || a.parts == nil {
		a.version, a.total, a.parts, a.size = c.Version, c.Total, map[int][]byte{}, 0
	}
	if _, dup := a.parts[c.Seq]; !dup {
		a.size += len(c.Data)
		if a.size > maxASNBytes {
			a.parts, a.version = nil, ""
			a.mu.Unlock()
			s.log.Warn(threat.Name + ": base ASN trop grande, ignorée")
			return
		}
		a.parts[c.Seq] = c.Data
	}
	if len(a.parts) < a.total {
		a.mu.Unlock()
		return
	}
	data := make([]byte, 0, a.size)
	for i := 0; i < a.total; i++ {
		data = append(data, a.parts[i]...)
	}
	a.parts, a.version = nil, ""
	a.mu.Unlock()

	db, err := asncompact.Decode(data)
	if err != nil {
		s.log.Warn(threat.Name+": base ASN reçue illisible, ignorée", "err", err)
		return
	}
	if db.Version() != c.Version {
		s.log.Warn(threat.Name+": base ASN reçue d'une autre version que celle annoncée, ignorée", "annoncée", c.Version, "reçue", db.Version())
		return
	}
	s.asnDB.Store(db)
	if err := s.cache.SaveFile(asnPath(), asnFile{Version: db.Version(), Data: data}); err != nil {
		s.log.Warn(threat.Name+": copie locale de la base ASN échouée", "err", err)
	}
	v4, v6 := db.Len()
	s.log.Info(threat.Name+": base ASN installée", "version", db.Version(), "plages_ipv4", v4, "plages_ipv6", v6)
}
