// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Import de liste : formats acceptés pour créer des bans (ou des entrées de la liste blanche) en une
// fois. Le format « texte » est celui des listes publiques (une adresse ou un CIDR par ligne,
// commentaires avec # ou ;), le CSV et le JSON sont ceux de l'export des bans, qui se réimporte tel quel.

// Limites d'un import : au-delà, la liste doit être découpée.
const (
	MaxImportBytes   = 2 << 20
	MaxImportEntries = 10000
)

// Formats d'import.
const (
	ImportFormatAuto = "auto"
	ImportFormatText = "text"
	ImportFormatCSV  = "csv"
	ImportFormatJSON = "json"
)

// ImportEntry est une ligne lue : la valeur brute (non validée) et ses informations facultatives.
type ImportEntry struct {
	// Line : numéro de ligne (texte, CSV) ou rang (JSON, à partir de 1), pour situer une erreur.
	Line      int
	Value     string
	Reason    string
	Domain    string
	ExpiresAt string
}

// ParseImport lit une liste dans le format demandé (auto : détecté) et retourne les entrées dans
// l'ordre, avec le format effectivement utilisé. Une entrée dont la valeur est invalide n'est pas
// écartée ici : la validation est faite par l'appelant, qui la signale ligne par ligne.
func ParseImport(content, format string) ([]ImportEntry, string, error) {
	if len(content) > MaxImportBytes {
		return nil, "", fmt.Errorf("liste trop volumineuse (%d octets, maximum %d) : la découper", len(content), MaxImportBytes)
	}
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	if strings.TrimSpace(content) == "" {
		return nil, "", fmt.Errorf("liste vide")
	}
	if format == "" || format == ImportFormatAuto {
		format = detectImportFormat(content)
	}
	var (
		entries []ImportEntry
		err     error
	)
	switch format {
	case ImportFormatText:
		entries = parseImportText(content)
	case ImportFormatCSV:
		entries, err = parseImportCSV(content)
	case ImportFormatJSON:
		entries, err = parseImportJSON(content)
	default:
		return nil, "", fmt.Errorf("format inconnu %q (text, csv ou json)", format)
	}
	if err != nil {
		return nil, format, err
	}
	if len(entries) > MaxImportEntries {
		return nil, format, fmt.Errorf("%d entrées (maximum %d) : découper la liste", len(entries), MaxImportEntries)
	}
	if len(entries) == 0 {
		return nil, format, fmt.Errorf("aucune entrée dans la liste")
	}
	return entries, format, nil
}

// detectImportFormat reconnaît le JSON (commence par [ ou {), le CSV (une première ligne d'en-tête
// contenant une colonne ip/cidr/address, ou des champs séparés par des virgules) et sinon le texte.
func detectImportFormat(content string) string {
	t := strings.TrimSpace(content)
	if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{") {
		return ImportFormatJSON
	}
	first := strings.TrimSpace(strings.SplitN(t, "\n", 2)[0])
	if _, col := csvIPColumn(splitCSVLine(first)); col >= 0 {
		return ImportFormatCSV
	}
	return ImportFormatText
}

func splitCSVLine(line string) []string {
	r := csv.NewReader(strings.NewReader(line))
	r.FieldsPerRecord = -1
	rec, err := r.Read()
	if err != nil {
		return nil
	}
	return rec
}

// csvIPColumn cherche la colonne d'adresses dans une ligne d'en-tête.
func csvIPColumn(header []string) (names []string, col int) {
	names = make([]string, len(header))
	col = -1
	for i, h := range header {
		names[i] = strings.ToLower(strings.TrimSpace(h))
		if col < 0 && (names[i] == "ip" || names[i] == "cidr" || names[i] == "address" || names[i] == "adresse") {
			col = i
		}
	}
	return names, col
}

// parseImportText lit une adresse ou un CIDR par ligne. Un commentaire (# ou ;) devient le motif de
// l'entrée quand elle n'en a pas d'autre : « 192.0.2.0/24 ; SBL123456 » (liste Spamhaus DROP) donne
// le motif « SBL123456 ». Ce qui suit la valeur sur la même ligne, sans marqueur, est ignoré.
func parseImportText(content string) []ImportEntry {
	var out []ImportEntry
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		comment := ""
		if k := strings.IndexAny(line, "#;"); k >= 0 {
			comment = strings.TrimSpace(line[k+1:])
			line = strings.TrimSpace(line[:k])
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(fields) == 0 {
			continue
		}
		out = append(out, ImportEntry{Line: i + 1, Value: fields[0], Reason: truncateRunes(comment, 200)})
	}
	return out
}

// parseImportCSV lit un CSV avec en-tête (colonnes ip, reason, domain, expires_at ; les autres, comme
// id, source, edge_name, created_at de l'export, sont ignorées) ou sans en-tête (ip[,reason]).
func parseImportCSV(content string) ([]ImportEntry, error) {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.Comment = '#'
	records, err := readAllCSV(r)
	if err != nil {
		return nil, fmt.Errorf("CSV illisible : %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	names, ipCol := csvIPColumn(records[0])
	start := 1
	if ipCol < 0 { // pas d'en-tête : ip[,reason]
		ipCol, start = 0, 0
		names = []string{"ip", "reason"}
	}
	col := func(name string) int {
		for i, n := range names {
			if n == name {
				return i
			}
		}
		return -1
	}
	reasonCol, domainCol, expCol := col("reason"), col("domain"), col("expires_at")
	get := func(rec []string, i int) string {
		if i >= 0 && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	var out []ImportEntry
	for i := start; i < len(records); i++ {
		rec := records[i]
		out = append(out, ImportEntry{
			Line: i + 1, Value: get(rec, ipCol), Reason: truncateRunes(get(rec, reasonCol), 200),
			Domain: get(rec, domainCol), ExpiresAt: get(rec, expCol),
		})
	}
	return out, nil
}

func readAllCSV(r *csv.Reader) ([][]string, error) {
	var out [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
}

// parseImportJSON lit un tableau de chaînes (« 203.0.113.5 ») ou d'objets (ip, reason, domain,
// expires_at), c'est-à-dire le JSON de l'export des bans.
func parseImportJSON(content string) ([]ImportEntry, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(content)))
	var raw []json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("JSON illisible (tableau de chaînes ou d'objets attendu) : %w", err)
	}
	var out []ImportEntry
	for i, item := range raw {
		e := ImportEntry{Line: i + 1}
		var s string
		if json.Unmarshal(item, &s) == nil {
			e.Value = strings.TrimSpace(s)
		} else {
			var o struct {
				IP        string `json:"ip"`
				CIDR      string `json:"cidr"`
				Reason    string `json:"reason"`
				Domain    string `json:"domain"`
				ExpiresAt string `json:"expires_at"`
			}
			if err := json.Unmarshal(item, &o); err != nil {
				return nil, fmt.Errorf("entrée %d : chaîne ou objet attendu", i+1)
			}
			e.Value = strings.TrimSpace(o.IP)
			if e.Value == "" {
				e.Value = strings.TrimSpace(o.CIDR)
			}
			e.Reason, e.Domain, e.ExpiresAt = truncateRunes(o.Reason, 200), o.Domain, o.ExpiresAt
		}
		out = append(out, e)
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
