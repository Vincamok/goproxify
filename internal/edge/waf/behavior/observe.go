// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

// Observation suit une requête à travers la passerelle pour qu'elle ne soit versée qu'une fois au magasin : le WAF y note le score
// de ses règles et, s'il enregistre lui-même l'événement (route avec analyse comportementale), le dit ; Ephor verse sinon la
// requête une fois la réponse connue.
type Observation struct {
	waf      atomic.Int32
	recorded atomic.Bool
}

type obsKey struct{}

// WithObservation attache une observation neuve au contexte de la requête.
func WithObservation(ctx context.Context) (context.Context, *Observation) {
	o := &Observation{}
	return context.WithValue(ctx, obsKey{}, o), o
}

// ObservationFrom retourne l'observation de la requête, nil si elle n'en a pas (tests, appels hors passerelle).
func ObservationFrom(ctx context.Context) *Observation {
	o, _ := ctx.Value(obsKey{}).(*Observation)
	return o
}

// NoteWAFScore consigne le score des règles WAF déclenchées par la requête.
func (o *Observation) NoteWAFScore(score int) {
	if o != nil && score > 0 {
		o.waf.Store(int32(score))
	}
}

// WAFScore retourne le score noté par le WAF.
func (o *Observation) WAFScore() int {
	if o == nil {
		return 0
	}
	return int(o.waf.Load())
}

// MarkRecorded indique que l'événement de la requête est déjà dans le magasin.
func (o *Observation) MarkRecorded() {
	if o != nil {
		o.recorded.Store(true)
	}
}

// Recorded indique si l'événement de la requête est déjà dans le magasin.
func (o *Observation) Recorded() bool { return o != nil && o.recorded.Load() }

var assetExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".avif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
}

// IsAssetPath indique un chemin d'image, de feuille de style, de script ou de police.
func IsAssetPath(p string) bool {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		return assetExts[strings.ToLower(p[i:])]
	}
	return false
}

// EventFromRequest décrit une requête terminée pour le magasin. route est l'hôte de la route qui l'a servie ("" s'il n'y en a
// pas : la requête ne nourrit alors pas les références par route).
func EventFromRequest(r *http.Request, status, wafScore int, route string) Event {
	ev := Event{
		WafScore: wafScore,
		Status:   status,
		Method:   r.Method,
		Path:     r.URL.Path,
		UA:       r.UserAgent(),
		Route:    route,
	}
	if fp := tlsfp.FromContext(r.Context()); fp != nil {
		ev.TLS = fp.JA4
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "image", "style", "script", "font":
		ev.Asset = true
	}
	if !ev.Asset {
		ev.Asset = IsAssetPath(ev.Path)
	}
	ev.Page = !ev.Asset && r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
	return ev
}
