// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Liste blanche des bans : adresses et plages qu'aucun ban n'atteint et que Sentinel n'évalue pas.
//
// Les entrées (avec leur commentaire) sont gardées dans le réglage whitelistSetting. Elles sont
// recopiées dans un profil IP en mode allow, d'identifiant router.WhitelistProfileID, que les
// passerelles reçoivent et conservent comme les autres profils : elles l'appliquent donc sans
// l'Admin, y compris après un redémarrage.

const (
	whitelistSetting     = "bans.whitelist"
	whitelistProfileName = "Liste blanche (bans)"
)

// WhitelistEntry est une adresse ou une plage exemptée.
type WhitelistEntry struct {
	Value   string    `json:"value"`
	Comment string    `json:"comment,omitempty"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// LoadWhitelist lit la liste blanche, triée par valeur.
func LoadWhitelist(db *sql.DB) []WhitelistEntry {
	var list []WhitelistEntry
	_ = json.Unmarshal([]byte(admindb.GetSetting(db, whitelistSetting, "[]")), &list)
	if list == nil {
		list = []WhitelistEntry{}
	}
	return list
}

// WhitelistCovering retourne l'entrée qui contient entièrement la cible (la cible est alors exemptée).
func WhitelistCovering(list []WhitelistEntry, target netip.Prefix) (WhitelistEntry, bool) {
	for _, e := range list {
		p, err := ParseTraceTarget(e.Value)
		if err == nil && p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return e, true
		}
	}
	return WhitelistEntry{}, false
}

// WhitelistOverlapping retourne les entrées qui recoupent la cible sans nécessairement la contenir.
func WhitelistOverlapping(list []WhitelistEntry, target netip.Prefix) []WhitelistEntry {
	out := []WhitelistEntry{}
	for _, e := range list {
		if TraceOverlap(target, e.Value) {
			out = append(out, e)
		}
	}
	return out
}

// AddWhitelist ajoute une entrée. added est faux si la cible est déjà couverte par une entrée
// existante (covering la désigne) ; dans ce cas rien ne change. Le profil IP est synchronisé.
func AddWhitelist(db *sql.DB, t BanTarget, comment, actor string) (entry WhitelistEntry, added bool, covering WhitelistEntry, err error) {
	list := LoadWhitelist(db)
	if c, ok := WhitelistCovering(list, t.Prefix); ok {
		return WhitelistEntry{}, false, c, nil
	}
	entry = WhitelistEntry{Value: t.Value, Comment: comment, AddedBy: actor, AddedAt: time.Now().UTC().Truncate(time.Second)}
	// Les entrées plus précises que la nouvelle deviennent redondantes : on les retire.
	kept := list[:0:0]
	for _, e := range list {
		if p, perr := ParseTraceTarget(e.Value); perr == nil && t.Prefix.Bits() <= p.Bits() && t.Prefix.Contains(p.Addr()) {
			continue
		}
		kept = append(kept, e)
	}
	list = append(kept, entry)
	return entry, true, WhitelistEntry{}, saveWhitelist(db, list)
}

// RemoveWhitelist retire l'entrée de cette valeur exacte ; faux si elle n'existe pas.
func RemoveWhitelist(db *sql.DB, t BanTarget) (bool, error) {
	list := LoadWhitelist(db)
	kept := list[:0:0]
	found := false
	for _, e := range list {
		if e.Value == t.Value {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return false, nil
	}
	return true, saveWhitelist(db, kept)
}

func saveWhitelist(db *sql.DB, list []WhitelistEntry) error {
	sort.Slice(list, func(i, j int) bool { return list[i].Value < list[j].Value })
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := admindb.SetSetting(db, whitelistSetting, string(raw)); err != nil {
		return err
	}
	return syncWhitelistProfile(db, list)
}

// syncWhitelistProfile recopie les entrées dans le profil allow que les passerelles reçoivent. Une
// liste vide supprime le profil, pour ne pas encombrer la page Profils IP.
func syncWhitelistProfile(db *sql.DB, list []WhitelistEntry) error {
	if len(list) == 0 {
		_, err := db.Exec(`DELETE FROM ip_profiles WHERE id=?`, router.WhitelistProfileID)
		return err
	}
	cidrs := make([]string, len(list))
	for i, e := range list {
		cidrs[i] = e.Value
	}
	raw, _ := json.Marshal(cidrs)
	_, err := db.Exec(
		`INSERT INTO ip_profiles (id, name, profile_type, mode, cidrs, enabled) VALUES (?, ?, 'custom', 'allow', ?, 1)
		 ON CONFLICT(id) DO UPDATE SET cidrs=excluded.cidrs, mode='allow', enabled=1, updated_at=CURRENT_TIMESTAMP`,
		router.WhitelistProfileID, whitelistProfileName, string(raw))
	return err
}

// ErrBanWhitelisted : la cible est entièrement couverte par la liste blanche, un ban n'aurait aucun effet.
type ErrBanWhitelisted struct {
	Target string
	Entry  WhitelistEntry
}

func (e ErrBanWhitelisted) Error() string {
	return "« " + e.Target + " » est en liste blanche (" + e.Entry.Value + ") : un ban n'aurait aucun effet ; retirer d'abord l'entrée de la liste blanche"
}

// CheckBanWhitelist refuse un ban dont la cible est entièrement couverte par la liste blanche. Une
// plage qui ne fait que recouper une entrée reste permise : l'entrée en reste exemptée.
func CheckBanWhitelist(db *sql.DB, t BanTarget) error {
	if e, ok := WhitelistCovering(LoadWhitelist(db), t.Prefix); ok {
		return ErrBanWhitelisted{Target: t.Value, Entry: e}
	}
	return nil
}

// WhitelistInput est une entrée à ajouter en lot.
type WhitelistInput struct {
	Target  BanTarget
	Comment string
}

// AddWhitelistMany ajoute plusieurs entrées d'un coup (une seule sauvegarde et une seule synchronisation
// du profil). Même règles que AddWhitelist : une entrée déjà couverte est comptée dans covered sans
// rien changer, une entrée plus large retire les plus précises. added liste les entrées créées.
func AddWhitelistMany(db *sql.DB, items []WhitelistInput, actor string) (added []WhitelistEntry, covered int, err error) {
	list := LoadWhitelist(db)
	now := time.Now().UTC().Truncate(time.Second)
	for _, it := range items {
		if _, ok := WhitelistCovering(list, it.Target.Prefix); ok {
			covered++
			continue
		}
		kept := list[:0:0]
		for _, e := range list {
			if p, perr := ParseTraceTarget(e.Value); perr == nil && it.Target.Prefix.Bits() <= p.Bits() && it.Target.Prefix.Contains(p.Addr()) {
				continue
			}
			kept = append(kept, e)
		}
		e := WhitelistEntry{Value: it.Target.Value, Comment: it.Comment, AddedBy: actor, AddedAt: now}
		list = append(kept, e)
		added = append(added, e)
	}
	if len(added) == 0 {
		return nil, covered, nil
	}
	// Une entrée ajoutée plus tôt peut avoir été absorbée par une plus large du même lot.
	final := make(map[string]bool, len(list))
	for _, e := range list {
		final[e.Value] = true
	}
	kept := added[:0:0]
	for _, e := range added {
		if final[e.Value] {
			kept = append(kept, e)
		}
	}
	return kept, covered, saveWhitelist(db, list)
}
