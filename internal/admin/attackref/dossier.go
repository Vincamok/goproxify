// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxDossierPaths = 200
	maxDistinctRaw  = 64
	maxSample       = 200
)

// Line est une ligne d'accès, réduite à ce que le dossier retient.
type Line struct {
	Ts     time.Time
	Domain string
	Method string
	Path   string
	Status int
	WAF    []string
	Signal string
}

// BanInfo est le ban qui déclenche un dossier.
type BanInfo struct {
	IP        string
	At        time.Time
	Source    string
	Reason    string
	UserAgent string
	Signals   []string
}

// PathHit est ce qu'une IP a demandé sous un gabarit : une méthode, un gabarit, des compteurs. Sample est un chemin
// réel, borné, qui permet à l'administrateur de reconnaître l'attaque.
type PathHit struct {
	Method      string         `json:"method"`
	Template    string         `json:"template"`
	Family      Family         `json:"family"`
	Count       int            `json:"count"`
	DistinctRaw int            `json:"distinct_raw"`
	Statuses    map[string]int `json:"statuses"`
	Sample      string         `json:"sample"`
	First       time.Time      `json:"first"`
	Last        time.Time      `json:"last"`
}

// Dossier résume ce qu'une IP bannie a fait autour de son ban : un résumé, pas une copie des lignes.
type Dossier struct {
	IP            string          `json:"ip"`
	BannedAt      time.Time       `json:"banned_at"`
	Source        string          `json:"source"`
	Reason        string          `json:"reason"`
	UserAgent     string          `json:"user_agent,omitempty"`
	UAFamily      string          `json:"ua_family,omitempty"`
	Signals       []string        `json:"signals,omitempty"`
	Requests      int             `json:"requests"`
	DistinctPaths int             `json:"distinct_paths"`
	Statuses      map[string]int  `json:"statuses"`
	Methods       map[string]int  `json:"methods"`
	WAF           map[string]int  `json:"waf"`
	Domains       int             `json:"domains"`
	First         time.Time       `json:"first,omitempty"`
	Last          time.Time       `json:"last,omitempty"`
	Paths         []PathHit       `json:"paths"`
	Profiles      []ProfileReason `json:"profiles"`
	Families      []Family        `json:"families"`
}

// BuildDossier résume les lignes d'une IP autour de son ban. Les lignes système (statut 0) sont ignorées.
func BuildDossier(ban BanInfo, lines []Line) Dossier {
	d := Dossier{
		IP: ban.IP, BannedAt: ban.At.UTC(), Source: ban.Source, Reason: clip(ban.Reason, maxSample), Signals: ban.Signals,
		UserAgent: clip(ban.UserAgent, 300), UAFamily: NormalizeUA(ban.UserAgent),
		Statuses: map[string]int{}, Methods: map[string]int{}, WAF: map[string]int{}, Paths: []PathHit{},
	}
	type key struct{ method, template string }
	hits := map[key]*PathHit{}
	raws := map[key]map[string]struct{}{}
	domains := map[string]struct{}{}
	templates := map[string]struct{}{}

	for _, l := range lines {
		if l.Status == 0 {
			continue
		}
		d.Requests++
		d.Statuses[strconv.Itoa(l.Status/100)+"xx"]++
		method := strings.ToUpper(l.Method)
		d.Methods[method]++
		for _, c := range l.WAF {
			d.WAF[c]++
		}
		if l.Domain != "" {
			domains[l.Domain] = struct{}{}
		}
		if d.First.IsZero() || l.Ts.Before(d.First) {
			d.First = l.Ts.UTC()
		}
		if l.Ts.After(d.Last) {
			d.Last = l.Ts.UTC()
		}
		tpl := TemplatePath(l.Path)
		if tpl == "" {
			continue
		}
		templates[tpl] = struct{}{}
		k := key{method, tpl}
		h := hits[k]
		if h == nil {
			h = &PathHit{Method: method, Template: tpl, Family: PathFamily(tpl), Statuses: map[string]int{}, Sample: clip(l.Path, maxSample), First: l.Ts.UTC()}
			hits[k] = h
			raws[k] = map[string]struct{}{}
		}
		h.Count++
		h.Statuses[strconv.Itoa(l.Status)]++
		if l.Ts.UTC().After(h.Last) {
			h.Last = l.Ts.UTC()
		}
		if l.Ts.UTC().Before(h.First) {
			h.First = l.Ts.UTC()
		}
		if len(raws[k]) < maxDistinctRaw {
			raws[k][strings.ToLower(l.Path)] = struct{}{}
		}
		h.DistinctRaw = len(raws[k])
	}
	d.Domains = len(domains)
	d.DistinctPaths = len(templates)

	for _, h := range hits {
		d.Paths = append(d.Paths, *h)
	}
	sort.Slice(d.Paths, func(i, j int) bool {
		if d.Paths[i].Count != d.Paths[j].Count {
			return d.Paths[i].Count > d.Paths[j].Count
		}
		return d.Paths[i].Template < d.Paths[j].Template
	})
	if len(d.Paths) > maxDossierPaths {
		d.Paths = d.Paths[:maxDossierPaths]
	}
	d.Profiles = Classify(&d)
	d.Families = Families(&d)
	return d
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
