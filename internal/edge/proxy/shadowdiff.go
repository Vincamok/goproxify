// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"hash"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Comparaison des réponses en mode shadow : seuls les 8 premiers Mo sont hachés, la taille totale
// est comptée en entier. Rien n'est mis en mémoire.
const (
	shadowHashLimit  = 8 << 20
	shadowLogEveryNs = int64(10 * time.Second)
)

// shadowObs résume une réponse (primaire ou miroir) pour la comparaison.
type shadowObs struct {
	status int
	hdr    http.Header
	sum    []byte
	size   int64
}

// shadowTee accumule le hachage et la taille d'un corps de réponse.
type shadowTee struct {
	h    hash.Hash
	n    int64
	hdr  http.Header
	snap bool
}

func newShadowTee() *shadowTee { return &shadowTee{h: sha256.New()} }

func (t *shadowTee) write(b []byte) {
	if room := shadowHashLimit - t.n; room > 0 {
		if int64(len(b)) > room {
			t.h.Write(b[:room])
		} else {
			t.h.Write(b)
		}
	}
	t.n += int64(len(b))
}

func (t *shadowTee) observe(status int, hdr http.Header) *shadowObs {
	return &shadowObs{status: status, hdr: hdr, sum: t.h.Sum(nil), size: t.n}
}

// shadowHeaderSnapshot copie les en-têtes à comparer (clés canoniques).
func shadowHeaderSnapshot(src http.Header, names []string) http.Header {
	if len(names) == 0 {
		return nil
	}
	out := make(http.Header, len(names))
	for _, n := range names {
		if v, ok := src[http.CanonicalHeaderKey(n)]; ok {
			out[http.CanonicalHeaderKey(n)] = append([]string(nil), v...)
		}
	}
	return out
}

// compareShadow retourne les natures de différence : status, header, body.
func compareShadow(cfg *router.ShadowConfig, a, b *shadowObs) []string {
	var kinds []string
	if a.status != b.status {
		kinds = append(kinds, "status")
	}
	for _, n := range cfg.CompareHeaders {
		k := http.CanonicalHeaderKey(n)
		if strings.Join(a.hdr[k], ",") != strings.Join(b.hdr[k], ",") {
			kinds = append(kinds, "header")
			break
		}
	}
	if cfg.CompareBody && (a.size != b.size || string(a.sum) != string(b.sum)) {
		kinds = append(kinds, "body")
	}
	return kinds
}

// recordShadowDiff compte la comparaison et journalise un échantillon (au plus un toutes les 10 s).
func (h *Handler) recordShadowDiff(method, uri string, primary, shadow *shadowObs) {
	host := h.route.Host
	metrics.Routing.ShadowCompared.WithLabelValues(host).Inc()
	kinds := compareShadow(h.route.Shadow, primary, shadow)
	for _, k := range kinds {
		metrics.Routing.ShadowDiff.WithLabelValues(host, k).Inc()
	}
	if len(kinds) == 0 {
		return
	}
	now := time.Now().UnixNano()
	last := h.shadowLogAt.Load()
	if now-last < shadowLogEveryNs || !h.shadowLogAt.CompareAndSwap(last, now) {
		return
	}
	h.log.Warn("shadow: réponses différentes", "host", host, "method", method, "uri", uri,
		"diff", strings.Join(kinds, ","), "primary_status", primary.status, "shadow_status", shadow.status,
		"primary_bytes", primary.size, "shadow_bytes", shadow.size)
}
