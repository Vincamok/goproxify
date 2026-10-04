// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// Le résumé d'une section chiffrée n'a besoin que de noms et de comptes. Décoder la section en
// structures Go (toutes les lignes, tous les fichiers) multipliait sa taille en mémoire ; on la lit donc
// en flux et chaque valeur est jetée aussitôt comptée.

func expectDelim(dec *json.Decoder, d json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t != d {
		return errors.New("format invalide")
	}
	return nil
}

// walkObject appelle fn(clé) pour chaque entrée de l'objet JSON courant ; fn doit consommer la valeur.
func walkObject(dec *json.Decoder, fn func(key string) error) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return errors.New("format invalide")
		}
		if err := fn(key); err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

func skipValue(dec *json.Decoder) error {
	var skip json.RawMessage
	return dec.Decode(&skip)
}

// countRows lit un tableau JSON (ou null) et renvoie son nombre d'éléments, sans les conserver.
func countRows(dec *json.Decoder) (int, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if t == nil {
		return 0, nil // null
	}
	if t != json.Delim('[') {
		return 0, errors.New("format invalide")
	}
	n := 0
	for dec.More() {
		if err := skipValue(dec); err != nil {
			return 0, err
		}
		n++
	}
	return n, expectDelim(dec, ']')
}

// summarizeTables lit un objet « table → lignes » et renvoie le nombre de lignes de chaque table non vide.
func summarizeTables(dec *json.Decoder) (map[string]int, error) {
	out := map[string]int{}
	err := walkObjectOrNull(dec, func(table string) error {
		n, err := countRows(dec)
		if err == nil && n > 0 {
			out[table] = n
		}
		return err
	})
	return out, err
}

// summarizeSecretsPlain résume une section secrets déchiffrée (SecretBundle) sans la décoder en entier.
func summarizeSecretsPlain(plain []byte) (*SecretsSummary, error) {
	dec := json.NewDecoder(bytes.NewReader(plain))
	sum := &SecretsSummary{Tables: map[string]int{}}
	seen := map[string]bool{}
	err := walkObject(dec, func(key string) error {
		switch key {
		case "tables":
			t, err := summarizeTables(dec)
			sum.Tables = t
			return err
		case "files":
			// null (omitempty) ou objet « nom → contenu » : seuls les noms comptent.
			return walkObjectOrNull(dec, func(name string) error {
				sum.Files++
				label, rest, _ := strings.Cut(name, "/")
				switch label {
				case gatewayLabel:
					if node, _, ok := strings.Cut(rest, "/"); ok && !seen[node] {
						seen[node] = true
						if n, err := url.PathUnescape(node); err == nil {
							sum.Gateways = append(sum.Gateways, n)
						}
					}
				case "config":
					sum.ConfigFiles = append(sum.ConfigFiles, rest)
				}
				return skipValue(dec)
			})
		default:
			return skipValue(dec)
		}
	})
	if err != nil {
		return nil, errors.New("section secrets : " + err.Error())
	}
	sort.Strings(sum.Gateways)
	sort.Strings(sum.ConfigFiles)
	return sum, nil
}

// walkObjectOrNull est walkObject qui accepte aussi null.
func walkObjectOrNull(dec *json.Decoder, fn func(key string) error) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return nil
	}
	if t != json.Delim('{') {
		return errors.New("format invalide")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := kt.(string)
		if !ok {
			return errors.New("format invalide")
		}
		if err := fn(key); err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

// summarizeHistoryPlain résume une section historique déchiffrée (HistoryBundle).
func summarizeHistoryPlain(plain []byte) (*HistorySummary, error) {
	dec := json.NewDecoder(bytes.NewReader(plain))
	sum := &HistorySummary{Tables: map[string]int{}}
	err := walkObject(dec, func(key string) error {
		switch key {
		case "tables":
			t, err := summarizeTables(dec)
			sum.Tables = t
			return err
		case "truncated":
			return dec.Decode(&sum.Truncated)
		default:
			return skipValue(dec)
		}
	})
	if err != nil {
		return nil, errors.New("historique : " + err.Error())
	}
	return sum, nil
}
