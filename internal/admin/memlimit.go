// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// memLimitShare : part de la limite mémoire du conteneur laissée au tas Go ; le reste couvre la pile,
// les tampons du système et les bibliothèques C.
const memLimitShare = 0.85

// parseCgroupLimit lit une limite de mémoire cgroup (v2 : memory.max, v1 : memory.limit_in_bytes).
// « max » ou une valeur absurde (v1 sans limite) signifient qu'il n'y en a pas.
func parseCgroupLimit(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 || n >= 1<<50 {
		return 0, false
	}
	return n, true
}

// containerMemoryLimit renvoie la limite mémoire du conteneur, si elle existe.
func containerMemoryLimit(read func(string) ([]byte, error)) (int64, bool) {
	for _, p := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		if b, err := read(p); err == nil {
			if n, ok := parseCgroupLimit(string(b)); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// parseMemTotal lit MemTotal (en octets) dans le contenu de /proc/meminfo.
func parseMemTotal(meminfo string) (int64, bool) {
	for _, line := range strings.Split(meminfo, "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || kb <= 0 {
			return 0, false
		}
		return kb << 10, true
	}
	return 0, false
}

// hostMemShare : sans limite de conteneur, part de la mémoire de la machine laissée au tas Go de l'Admin ;
// le reste revient aux autres conteneurs et au système.
const hostMemShare = 0.5

// applyMemoryLimit règle la limite souple de mémoire du runtime Go sur la limite du conteneur : près de
// cette limite, le ramasse-miettes travaille davantage au lieu de laisser le tas doubler, ce qui évite
// qu'une sauvegarde volumineuse fasse tuer l'Admin faute de mémoire. Sans effet si GOMEMLIMIT est défini
// ou si le conteneur n'a pas de limite.
func applyMemoryLimit(log *slog.Logger, read func(string) ([]byte, error)) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	if limit, ok := containerMemoryLimit(read); ok {
		soft := int64(float64(limit) * memLimitShare)
		debug.SetMemoryLimit(soft)
		log.Info("mémoire : limite souple du runtime alignée sur celle du conteneur", "conteneur_mo", limit>>20, "runtime_mo", soft>>20)
		return
	}
	// Pas de limite de conteneur : l'Admin peut consommer toute la RAM de la machine et se faire abattre
	// par le noyau (observé sur une VM de 2 Go). On plafonne donc le tas à la moitié de la mémoire de la machine.
	if b, err := read("/proc/meminfo"); err == nil {
		if total, ok := parseMemTotal(string(b)); ok {
			soft := int64(float64(total) * hostMemShare)
			debug.SetMemoryLimit(soft)
			log.Info("mémoire : conteneur sans limite, limite souple du runtime fixée à la moitié de la mémoire de la machine", "machine_mo", total>>20, "runtime_mo", soft>>20)
		}
	}
}
