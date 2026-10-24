// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package pairing

import (
	"os"
	"strings"
	"time"
)

// Key est une clé que l'on accepte en vérification. Previous : elle vient d'un secret en cours de remplacement
// (`<NOM>_PREVIOUS`), accepté le temps de la bascule seulement.
type Key struct {
	Value    string
	Previous bool
}

// Secret lit un secret : la variable NOM, sinon le contenu du fichier désigné par NOM_FILE (un secret Docker, par
// exemple). Le fichier est relu à chaque appel : une valeur changée sur disque est prise en compte sans redémarrage.
func Secret(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if path := os.Getenv(name + "_FILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// Previous lit les valeurs précédentes d'un secret : NOM_PREVIOUS, ou le fichier NOM_PREVIOUS_FILE, séparées par des
// virgules, des espaces ou des retours à la ligne. Si NOM_PREVIOUS_UNTIL est posée (date RFC 3339), elles cessent d'être
// acceptées à cette date : la fin du recouvrement n'attend pas que l'opérateur y pense. Une date illisible les
// supprime aussi, puisqu'on ne sait pas jusqu'à quand les accepter.
func Previous(name string) []string {
	return previousAt(name, time.Now())
}

func previousAt(name string, now time.Time) []string {
	if until := strings.TrimSpace(os.Getenv(name + "_PREVIOUS_UNTIL")); until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil || !now.Before(t) {
			return nil
		}
	}
	raw := os.Getenv(name + "_PREVIOUS")
	if raw == "" {
		if path := os.Getenv(name + "_PREVIOUS_FILE"); path != "" {
			if data, err := os.ReadFile(path); err == nil {
				raw = string(data)
			}
		}
	}
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// Keys donne la valeur courante d'un secret, puis ses valeurs précédentes (marquées), sans doublon ni valeur vide.
func Keys(name string) []Key {
	var out []Key
	seen := map[string]bool{}
	if cur := Secret(name); cur != "" {
		out = append(out, Key{Value: cur})
		seen[cur] = true
	}
	for _, p := range Previous(name) {
		if p != "" && !seen[p] {
			out = append(out, Key{Value: p, Previous: true})
			seen[p] = true
		}
	}
	return out
}

// Current rend la valeur courante d'une liste de clés ("" s'il n'y en a pas).
func Current(keys []Key) string {
	for _, k := range keys {
		if !k.Previous {
			return k.Value
		}
	}
	return ""
}

// RootKeys : le secret racine courant et ses précédents (GPX_PAIRING_SECRET, GPX_PAIRING_SECRET_PREVIOUS).
func RootKeys() []Key { return Keys("GPX_PAIRING_SECRET") }

// AgentKeysFromRoots dérive la clé des Agents de chaque secret racine.
func AgentKeysFromRoots(roots []Key) []Key {
	out := make([]Key, 0, len(roots))
	for _, r := range roots {
		out = append(out, Key{Value: AgentKey(r.Value), Previous: r.Previous})
	}
	return out
}

// EdgeAdminKeys : les clés avec lesquelles une passerelle vérifie la signature de l'Admin. Sa clé de canal
// (GPX_EDGE_CHANNEL_KEY) d'abord, puis le secret racine pour les installations qui ne l'ont pas encore retiré de la
// passerelle ; chacune avec ses valeurs précédentes pendant une rotation.
func EdgeAdminKeys() []Key {
	return append(Keys("GPX_EDGE_CHANNEL_KEY"), RootKeys()...)
}

// EdgeAgentKeys : les clés d'appairage des Agents que la passerelle accepte. GPX_AGENT_PAIRING_KEY si elle est posée (la
// passerelle n'a alors pas besoin du secret racine), sinon dérivées du secret racine.
func EdgeAgentKeys() []Key {
	if keys := Keys("GPX_AGENT_PAIRING_KEY"); len(keys) > 0 {
		return keys
	}
	return AgentKeysFromRoots(RootKeys())
}

// ServerAcceptsAgentKeys indique si le secret présenté par un Agent est l'une des clés des Agents, ou (sauf
// GPX_AGENT_PAIRING_ROOT=false) l'un des secrets racine. viaRoot : l'Agent a présenté la racine ; previous : la clé
// présentée est une valeur précédente.
func ServerAcceptsAgentKeys(agentKeys, roots []Key, presented string) (ok, viaRoot, previous bool) {
	for _, k := range agentKeys {
		if Equal(k.Value, presented) {
			return true, false, k.Previous
		}
	}
	if os.Getenv("GPX_AGENT_PAIRING_ROOT") != "false" {
		for _, r := range roots {
			if Equal(r.Value, presented) {
				return true, true, r.Previous
			}
		}
	}
	return false, false, false
}

// AgentCredentials : ce qu'un Agent présente pour s'appairer, la valeur courante d'abord. GPX_AGENT_PAIRING_KEY, ou à
// défaut le secret racine d'une installation qui n'a pas migré (legacyRoot).
func AgentCredentials() (creds []Key, legacyRoot bool) {
	if keys := Keys("GPX_AGENT_PAIRING_KEY"); len(keys) > 0 {
		return keys, false
	}
	return RootKeys(), true
}

// AgentBearers : les valeurs que l'API interne de l'Agent accepte en Bearer de la part de l'Admin ou de sa passerelle,
// pour la clé courante comme pour les précédentes.
func AgentBearers() []string {
	creds, _ := AgentCredentials()
	var out []string
	for _, c := range creds {
		out = append(out, AgentAccepts(c.Value)...)
	}
	return out
}
