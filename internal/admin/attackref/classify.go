// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"sort"
	"strconv"
	"strings"
)

// Family est la famille d'une attaque (ADR 0023, taxonomie alignée sur les catégories du WAF).
type Family string

const (
	FamilyConfigLeak      Family = "config_leak"
	FamilyCMSProbe        Family = "cms_probe"
	FamilyAdminProbe      Family = "admin_panel_probe"
	FamilyScanner         Family = "scanner_generic"
	FamilySQLi            Family = "sqli"
	FamilyXSS             Family = "xss"
	FamilyLFI             Family = "lfi"
	FamilyRCE             Family = "rce"
	FamilyBruteforce      Family = "bruteforce"
	FamilyEnumeration     Family = "enumeration"
	FamilyExploitCVE      Family = "exploit_cve"
	FamilyUnclassified    Family = "unclassified"
	FamilyOffensiveClient Family = "offensive_tool"
)

// Profile est ce que l'attaquant a été, d'après son dossier (règles déterministes, expliquées par Reasons).
type Profile string

const (
	ProfileExploiter    Profile = "exploiter"
	ProfileBruteforcer  Profile = "bruteforcer"
	ProfileEnumerator   Profile = "enumerator"
	ProfileScanner      Profile = "scanner"
	ProfileAbusiveBot   Profile = "crawler_abusif"
	ProfileUnclassified Profile = "unclassified"
)

type pathRule struct {
	family Family
	any    []string
}

var pathRules = []pathRule{
	{FamilyLFI, []string{"../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self", "boot.ini", "win.ini"}},
	{FamilyRCE, []string{"jndi:", "${", "/eval-stdin", "/shell", "cmd.exe", "/bin/sh", "/bin/bash", "wget%20", "curl%20"}},
	{FamilyExploitCVE, []string{"/cgi-bin/", "/vendor/phpunit", "/boaform", "/_ignition", "/hnap1", "/gponform", "/setup.cgi",
		"/containers/json", "/api/jsonws", "/ecp/", "/owa/auth", "/solr/", "/struts", "/invoker/", "/jmx-console", "/hudson", "/telescope"}},
	{FamilyConfigLeak, []string{".env", "/.git", "/.svn", "/.hg", ".htpasswd", ".htaccess", "wp-config", "config.php", "configuration.php",
		"config.json", "config.yml", "config.yaml", "settings.py", "web.config", ".aws", "id_rsa", ".ds_store", "composer.json", "composer.lock",
		"package.json", "docker-compose", ".npmrc", ".bak", ".old", ".orig", ".sql", ".dump", "/backup", "/dump", ".tar", ".zip", ".gz", ".7z", ".rar",
		"phpinfo", "/.idea", "/.vscode", "/server-status", "/server-info"}},
	{FamilyCMSProbe, []string{"/wp-", "wordpress", "xmlrpc.php", "/joomla", "/drupal", "/typo3", "/magento", "/prestashop", "/administrator/", "/sites/default"}},
	{FamilyAdminProbe, []string{"phpmyadmin", "/pma", "/adminer", "/admin", "/manager/html", "/console", "/cpanel", "/actuator", "/jenkins", "/grafana", "/login.php", "/wp-login"}},
}

// PathFamily classe un gabarit de chemin ; FamilyScanner quand aucune règle ne le reconnaît (un chemin sondé qui n'existe pas).
func PathFamily(template string) Family {
	for _, r := range pathRules {
		for _, s := range r.any {
			if strings.Contains(template, s) {
				return r.family
			}
		}
	}
	return FamilyScanner
}

var exploitCategories = map[string]Family{
	"sqli": FamilySQLi, "xss": FamilyXSS, "lfi": FamilyLFI, "rce": FamilyRCE, "traversal": FamilyLFI,
}

var loginLike = []string{"login", "signin", "auth", "session", "token", "xmlrpc", "wp-login", "admin", "password"}

// ProfileReason dit pourquoi un profil a été retenu.
type ProfileReason struct {
	Profile Profile `json:"profile"`
	Why     string  `json:"why"`
}

// Classify attribue les profils d'un dossier, du plus grave au plus bénin ; d'abord le principal. Les seuils sont
// volontairement simples : chaque profil se vérifie à la main sur le dossier.
func Classify(d *Dossier) []ProfileReason {
	var out []ProfileReason
	add := func(p Profile, why string) { out = append(out, ProfileReason{p, why}) }

	exploit := 0
	for cat, n := range d.WAF {
		if _, ok := exploitCategories[cat]; ok {
			exploit += n
		}
	}
	if exploit > 0 {
		add(ProfileExploiter, "catégories WAF d'exploitation déclenchées "+strconv.Itoa(exploit)+" fois")
	}

	for _, p := range d.Paths {
		if p.Method != "POST" || p.Count < 8 {
			continue
		}
		login := false
		for _, l := range loginLike {
			if strings.Contains(p.Template, l) {
				login = true
				break
			}
		}
		denied := p.Statuses["401"] + p.Statuses["403"]
		if login || denied*2 >= p.Count {
			add(ProfileBruteforcer, strconv.Itoa(p.Count)+" POST vers "+p.Template)
			break
		}
	}

	for _, p := range d.Paths {
		if strings.Contains(p.Template, "{") && p.Count >= 30 && p.DistinctRaw >= 10 {
			add(ProfileEnumerator, strconv.Itoa(p.DistinctRaw)+" valeurs distinctes sous "+p.Template)
			break
		}
	}

	if d.DistinctPaths >= 10 && d.Statuses["4xx"]*10 >= d.Requests*7 {
		add(ProfileScanner, strconv.Itoa(d.DistinctPaths)+" chemins distincts, "+strconv.Itoa(d.Statuses["4xx"])+" réponses 4xx sur "+strconv.Itoa(d.Requests))
	}

	if d.Requests >= 200 && d.Statuses["2xx"]*10 >= d.Requests*8 && len(out) == 0 {
		add(ProfileAbusiveBot, strconv.Itoa(d.Requests)+" requêtes réussies en rafale")
	}

	if len(out) == 0 {
		add(ProfileUnclassified, "aucun profil ne correspond")
	}
	return out
}

// Families rend les familles d'attaque d'un dossier, de la plus fréquente à la moins fréquente.
func Families(d *Dossier) []Family {
	counts := map[Family]int{}
	for _, p := range d.Paths {
		counts[p.Family] += p.Count
	}
	for cat, n := range d.WAF {
		if f, ok := exploitCategories[cat]; ok {
			counts[f] += n
		}
	}
	if d.UAFamily != "" {
		counts[FamilyOffensiveClient]++
	}
	out := make([]Family, 0, len(counts))
	for f := range counts {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
