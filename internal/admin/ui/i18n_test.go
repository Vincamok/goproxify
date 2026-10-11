// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"regexp"
	"strings"
	"testing"
)

// localeBlocks découpe shared/i18n.js en blocs par langue (« en: { … } », « fr: { … } »…).
func localeBlocks(t *testing.T) map[string]string {
	t.Helper()
	b, err := srcFS.ReadFile("src/js/shared/i18n.js")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	langs := []string{"en", "fr", "es", "de"}
	pos := map[string]int{}
	for _, l := range langs {
		i := strings.Index(src, "\n  "+l+": {\n")
		if i < 0 {
			t.Fatalf("bloc %q introuvable", l)
		}
		pos[l] = i
	}
	out := map[string]string{}
	for idx, l := range langs {
		end := len(src)
		if idx+1 < len(langs) {
			end = pos[langs[idx+1]]
		}
		out[l] = src[pos[l]:end]
	}
	return out
}

// Toute clé de traduction utilisée par les pages pilotées par les modules existe dans les quatre langues :
// une clé manquante s'afficherait en anglais (repli) ou, pire, sous sa forme brute.
func TestModulePagesAreFullyTranslated(t *testing.T) {
	blocks := localeBlocks(t)
	use := regexp.MustCompile(`\bt\('((?:ssop|plug|rtplug)\.[A-Za-z0-9_.-]+)'`)
	for _, file := range []string{"pages/auth-providers.js", "pages/plugins.js", "shared/proxy-plugins.js"} {
		b, err := srcFS.ReadFile("src/js/" + file)
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		for _, m := range use.FindAllStringSubmatch(string(b), -1) {
			keys[m[1]] = true
		}
		if len(keys) == 0 {
			t.Errorf("%s : aucune clé de traduction trouvée (texte en dur ?)", file)
		}
		for key := range keys {
			for lang, block := range blocks {
				if !strings.Contains(block, "'"+key+"':") {
					t.Errorf("%s : clé %q absente de la langue %s", file, key, lang)
				}
			}
		}
	}
	for _, key := range []string{"page.auth-providers", "page.plugins", "settings.item.auth_providers_desc", "settings.item.plugins_desc"} {
		for lang, block := range blocks {
			if !strings.Contains(block, "'"+key+"':") {
				t.Errorf("clé %q absente de la langue %s", key, lang)
			}
		}
	}
}

// Aucun texte français en dur dans les pages : les libellés passent par t().
func TestModulePagesHaveNoHardcodedFrench(t *testing.T) {
	accent := regexp.MustCompile(`[àâçéèêëîïôûùü]`)
	for _, file := range []string{"pages/auth-providers.js", "pages/plugins.js", "shared/proxy-plugins.js"} {
		b, err := srcFS.ReadFile("src/js/" + file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "*") {
				continue
			}
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = line[:idx]
			}
			if accent.MatchString(line) && !strings.Contains(line, "mon-plugin") {
				t.Errorf("%s:%d : texte accentué en dur : %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}

var automationPages = []string{"shared/flow-model.js", "pages/automation-flow.js", "pages/automation-lists.js", "pages/rules-store.js", "pages/automation.js"}

// Les pages des flux d'automatisation : chaque clé flow.* existe dans les quatre langues, y compris les
// clés construites (statut, source, catégorie…), et aucun texte français n'est écrit en dur.
func TestAutomationPagesAreFullyTranslated(t *testing.T) {
	blocks := localeBlocks(t)
	use := regexp.MustCompile(`\bt\('(flow\.[A-Za-z0-9_.-]+)'`)
	keys := map[string]bool{}
	for _, file := range automationPages {
		b, err := srcFS.ReadFile("src/js/" + file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range use.FindAllStringSubmatch(string(b), -1) {
			keys[m[1]] = true
		}
	}
	dynamic := map[string][]string{
		"flow.status_":     {"running", "waiting", "waiting_approval", "waiting_child", "completed", "stopped", "failed", "rejected", "silenced", "interrupted", "cancelled"},
		"flow.sim_":        {"simulated", "done", "failed", "skipped", "waiting", "approved", "rejected"},
		"flow.src_":        {"admin", "edge", "manual", "call"},
		"flow.f_":          {"all", "completed", "failed", "waiting", "stopped", "silenced", "edge"},
		"flow.cat_":        {"security", "reliability", "compliance", "maintenance", "remediation"},
		"flow.tab_":        {"rules", "schedules", "playbooks"},
		"flow.new_":        {"rules", "schedules", "playbooks"},
		"flow.empty_":      {"rules", "schedules", "playbooks"},
		"flow.list_hint_":  {"rules", "schedules", "playbooks"},
		"flow.ch_":         {"none", "created", "earliest_kept", "name", "description", "trigger_kind", "trigger", "guard", "origin", "params", "step_added", "step_removed", "step_changed", "step_moved"},
		"flow.ch_enabled_": {"true", "false"},
	}
	for prefix, suffixes := range dynamic {
		for _, s := range suffixes {
			keys[prefix+s] = true
		}
	}
	for key := range keys {
		if strings.HasSuffix(key, "_") {
			continue
		}
		for lang, block := range blocks {
			if !strings.Contains(block, "'"+key+"':") {
				t.Errorf("clé %q absente de la langue %s", key, lang)
			}
		}
	}
	accent := regexp.MustCompile(`[àâçéèêëîïôûùü]`)
	for _, file := range automationPages {
		b, _ := srcFS.ReadFile("src/js/" + file)
		for i, line := range strings.Split(string(b), "\n") {
			if trim := strings.TrimSpace(line); strings.HasPrefix(trim, "//") {
				continue
			}
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = line[:idx]
			}
			if accent.MatchString(line) {
				t.Errorf("%s:%d : texte accentué en dur : %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}
