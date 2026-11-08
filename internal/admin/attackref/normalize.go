// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package attackref construit le référentiel des attaques (ADR 0023) : pour chaque IP bannie, un dossier de ce qu'elle
// a fait, puis des entrées normalisées (chemins sondés, User-Agent d'outils) retenues seulement quand elles
// discriminent les attaquants des visiteurs. Rien ici ne contient d'IP dans une entrée, ni d'hôte, ni de valeur de
// paramètre.
package attackref

import (
	"math"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxSegments   = 12
	maxSegmentLen = 64
	maxPathLen    = 200
)

var (
	reInt  = regexp.MustCompile(`^[0-9]+$`)
	reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reDate = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	reHex  = regexp.MustCompile(`^[0-9a-f]{16,}$`)
)

// TemplatePath ramène un chemin à son gabarit : en minuscules, sans requête, avec les segments qui ressemblent à une
// valeur (nombre, UUID, date, hexadécimal long, jeton, adresse électronique) remplacés par une variable. Les
// séquences de remontée (`..`) sont gardées : ce sont elles qui désignent l'attaque. Un chemin illisible ou qui ne
// commence pas par « / » rend "".
func TemplatePath(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if dec, err := url.PathUnescape(raw); err == nil {
		raw = dec
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || raw[0] != '/' {
		return ""
	}
	parts := strings.Split(raw, "/")[1:]
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" {
			continue
		}
		if len(out) == maxSegments {
			break
		}
		out = append(out, segmentTemplate(seg))
	}
	t := "/" + strings.Join(out, "/")
	if strings.HasSuffix(raw, "/") && t != "/" {
		t += "/"
	}
	if len(t) > maxPathLen {
		t = t[:maxPathLen]
	}
	return t
}

func segmentTemplate(seg string) string {
	switch {
	case reInt.MatchString(seg):
		return "{int}"
	case reUUID.MatchString(seg):
		return "{uuid}"
	case reDate.MatchString(seg):
		return "{date}"
	case reHex.MatchString(seg):
		return "{hex}"
	case strings.Contains(seg, "@"):
		return "{var}"
	case looksLikeToken(seg):
		return "{token}"
	}
	if len(seg) > maxSegmentLen {
		return seg[:maxSegmentLen]
	}
	return seg
}

// looksLikeToken : un segment long, mêlant lettres et chiffres, ou d'entropie élevée, n'est pas un nom de fichier.
func looksLikeToken(s string) bool {
	if len(s) < 20 {
		return false
	}
	letters, digits := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'z':
			letters++
		}
	}
	if digits >= 4 && letters >= 4 {
		return true
	}
	return entropy(s) > 3.8
}

func entropy(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// LiteralPrefix rend la partie du gabarit avant la première variable : le préfixe qu'on peut chercher dans les logs.
func LiteralPrefix(template string) string {
	if i := strings.Index(template, "{"); i >= 0 {
		return template[:i]
	}
	return template
}

// offensiveTools : outils de scan, d'injection ou de force brute. Un User-Agent qui en porte le nom est retenu comme
// famille ; les clients HTTP génériques (curl, python-requests…) ne le sont pas, des clients légitimes les utilisent.
var offensiveTools = []string{
	"sqlmap", "nikto", "nuclei", "masscan", "zgrab", "nmap", "wpscan", "dirbuster", "dirb", "gobuster", "feroxbuster",
	"ffuf", "wfuzz", "hydra", "acunetix", "nessus", "openvas", "netsparker", "burpsuite", "zaproxy", "owasp zap",
	"l9explore", "l9tcpid", "censys", "shodan", "projectdiscovery", "httpx", "paros", "w3af", "arachni", "skipfish",
	"commix", "xsstrike", "whatweb", "jaeles", "dalfox", "katana", "gau", "fimap", "havij", "morfeus", "zmeu",
}

var reMajor = regexp.MustCompile(`^[ /v]*([0-9]+)`)

// NormalizeUA ramène un User-Agent à « outil/version majeure » quand il porte le nom d'un outil offensif connu ; ""
// sinon (navigateur, client générique ou inconnu : il ne peut être ni mesuré ni proposé, voir Entry.Lift).
func NormalizeUA(ua string) string {
	low := strings.ToLower(ua)
	for _, tool := range offensiveTools {
		i := strings.Index(low, tool)
		if i < 0 {
			continue
		}
		if m := reMajor.FindStringSubmatch(low[i+len(tool):]); m != nil {
			return tool + "/" + m[1] + ".x"
		}
		return tool
	}
	return ""
}
