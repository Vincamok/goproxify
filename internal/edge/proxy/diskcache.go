// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// DiskCache est un cache proxy HTTP sur disque (RFC 7234 simplifié).
type DiskCache struct {
	dir string
	mu  sync.Mutex

	fmu        sync.Mutex
	flights    map[string]*flight
	refreshing map[string]bool
}

// flight regroupe les requêtes simultanées sur une même clé : une seule
// interroge le backend, les autres attendent son résultat.
type flight struct {
	done chan struct{}
	res  *fetched
}

// New crée un DiskCache utilisant dir comme répertoire de stockage.
func New(dir string) *DiskCache {
	_ = os.MkdirAll(dir, 0o755)
	return &DiskCache{dir: dir, flights: map[string]*flight{}, refreshing: map[string]bool{}}
}

type cacheEntry struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
	Expires time.Time           `json:"expires"`
	// StaleUntil : fin de la fenêtre stale-while-revalidate (servie périmée pendant la revalidation).
	StaleUntil time.Time `json:"stale_until,omitempty"`
	// ErrorUntil : fin de la fenêtre stale-if-error (servie périmée si le backend échoue).
	ErrorUntil time.Time `json:"error_until,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	URI        string    `json:"uri,omitempty"`
}

func cacheKey(r *http.Request) string {
	raw := r.Method + r.Host + r.URL.Path + r.URL.RawQuery
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// variantKey affine la clé primaire avec les en-têtes listés par Vary et les
// cookies de cfg.VaryCookies, pour qu'une variante ne soit jamais servie à un
// client dont la requête diffère sur ces points.
func variantKey(primary string, r *http.Request, vary []string, cfg *router.CacheConfig) string {
	var b strings.Builder
	b.WriteString(primary)
	for _, h := range vary {
		b.WriteString("\x00" + h + "=" + strings.Join(r.Header.Values(h), "\x01"))
	}
	if cfg != nil {
		for _, name := range cfg.VaryCookies {
			v := ""
			if c, err := r.Cookie(name); err == nil {
				v = c.Value
			}
			b.WriteString("\x00c:" + name + "=" + v)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum)
}

// parseVary retourne les noms d'en-têtes de Vary (canonisés). star vaut vrai pour "Vary: *".
func parseVary(h http.Header) (names []string, star bool) {
	for _, line := range h.Values("Vary") {
		for _, n := range strings.Split(line, ",") {
			n = strings.TrimSpace(n)
			switch n {
			case "":
			case "*":
				star = true
			default:
				names = append(names, http.CanonicalHeaderKey(n))
			}
		}
	}
	sort.Strings(names)
	return names, star
}

// responseCacheable refuse toute réponse destinée à un seul client.
func responseCacheable(h http.Header) bool {
	if len(h.Values("Set-Cookie")) > 0 {
		return false
	}
	for _, line := range h.Values("Cache-Control") {
		for _, d := range strings.Split(line, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if i := strings.IndexByte(d, '='); i >= 0 {
				d = d[:i]
			}
			if d == "private" || d == "no-store" {
				return false
			}
		}
	}
	return true
}

func (dc *DiskCache) getRaw(key string) []byte {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	data, err := os.ReadFile(dc.filePath(key))
	if err != nil {
		return nil
	}
	return data
}

func (dc *DiskCache) setRaw(key string, data []byte) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	_ = os.WriteFile(dc.filePath(key), data, 0o644)
}

func (dc *DiskCache) filePath(key string) string {
	return fmt.Sprintf("%s/%s.json", dc.dir, key)
}

// load lit une entrée sans tenir compte de son expiration.
func (dc *DiskCache) load(key string) *cacheEntry {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	data, err := os.ReadFile(dc.filePath(key))
	if err != nil {
		return nil
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil || entry.Status == 0 {
		return nil
	}
	return &entry
}

func (dc *DiskCache) get(key string) *cacheEntry {
	entry := dc.load(key)
	if entry == nil || time.Now().After(entry.Expires) {
		return nil
	}
	return entry
}

func (dc *DiskCache) set(key string, entry *cacheEntry) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(dc.filePath(key), data, 0o644)
}

// Purge supprime toutes les entrées en cache de ce proxy (son répertoire est
// dédié : un dir par route, voir dispatch.go). Retourne le nombre de fichiers supprimés.
func (dc *DiskCache) Purge() (int, error) {
	return dc.PurgeMatching(PurgeSelector{})
}

// PurgeSelector cible des entrées : par tag (en-tête Cache-Tag / Surrogate-Key
// de la réponse) ou par URL (chemin, avec ou sans query ; suffixe "*" = préfixe).
// Un sélecteur vide vise tout le cache.
type PurgeSelector struct {
	Tags  []string `json:"tags,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (sel PurgeSelector) all() bool { return len(sel.Tags) == 0 && len(sel.Paths) == 0 }

func (sel PurgeSelector) matches(e *cacheEntry) bool {
	for _, want := range sel.Tags {
		for _, t := range e.Tags {
			if t == want {
				return true
			}
		}
	}
	path := e.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, p := range sel.Paths {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(e.URI, prefix) {
				return true
			}
		} else if p == e.URI || p == path {
			return true
		}
	}
	return false
}

// PurgeMatching supprime les entrées visées par sel et retourne leur nombre.
func (dc *DiskCache) PurgeMatching(sel PurgeSelector) (int, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	entries, err := os.ReadDir(dc.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := dc.dir + "/" + e.Name()
		if !sel.all() {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var entry cacheEntry
			if json.Unmarshal(data, &entry) != nil || entry.Status == 0 || !sel.matches(&entry) {
				continue
			}
		}
		if err := os.Remove(path); err == nil {
			n++
		}
	}
	return n, nil
}

// parseMaxAge extrait max-age depuis la valeur d'un header Cache-Control.
// Retourne -1 si absent ou invalide.
func parseMaxAge(cc string) int {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			val := strings.TrimPrefix(part, "max-age=")
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				return n
			}
		}
	}
	return -1
}

// parseDirective extrait la valeur entière (secondes) d'une directive
// Cache-Control (ex. stale-while-revalidate). Retourne -1 si absente ou invalide.
func parseDirective(cc, name string) int {
	for _, part := range strings.Split(cc, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), name+"="); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
				return n
			}
		}
	}
	return -1
}

// extractTags lit puis retire Cache-Tag (virgules) et Surrogate-Key (espaces) :
// ces en-têtes ne concernent que le cache, pas le client.
func extractTags(h http.Header) []string {
	var tags []string
	for _, name := range []string{"Cache-Tag", "Surrogate-Key"} {
		for _, line := range h.Values(name) {
			tags = append(tags, strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' })...)
		}
		h.Del(name)
	}
	return tags
}

// staleWindow retourne la durée de tolérance : directive du backend, sinon valeur de configuration.
func staleWindow(cc, directive, cfgValue string) time.Duration {
	if n := parseDirective(cc, directive); n >= 0 {
		return time.Duration(n) * time.Second
	}
	return parseTTL(cfgValue)
}

// responseRecorder capture la réponse du handler suivant.
type responseRecorder struct {
	code    int
	headers http.Header
	buf     bytes.Buffer
}

func (rr *responseRecorder) Header() http.Header         { return rr.headers }
func (rr *responseRecorder) WriteHeader(code int)        { rr.code = code }
func (rr *responseRecorder) Write(b []byte) (int, error) { return rr.buf.Write(b) }

// Middleware applique le cache disque (legacy : TTL depuis Cache-Control backend).
func (dc *DiskCache) Middleware(next http.Handler) http.Handler {
	return dc.MiddlewareWithConfig(nil)(next)
}

// MiddlewareWithConfig applique le cache disque avec configuration avancée.
func (dc *DiskCache) MiddlewareWithConfig(cfg *router.CacheConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		allowedMethods := map[string]bool{"GET": true, "HEAD": true}
		if cfg != nil && len(cfg.Methods) > 0 {
			allowedMethods = make(map[string]bool, len(cfg.Methods))
			for _, m := range cfg.Methods {
				allowedMethods[strings.ToUpper(m)] = true
			}
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowedMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Bypass : si un header ou cookie de bypass est présent et non vide
			if cfg != nil && isBypass(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Requête authentifiée ou avec cookies : réponse potentiellement propre
			// à l'utilisateur, jamais mise en cache ni resservie sauf option
			// explicite (ignore_cookies / vary_cookies).
			if r.Header.Get("Authorization") != "" ||
				(len(r.Cookies()) > 0 && (cfg == nil || !(cfg.IgnoreCookies || len(cfg.VaryCookies) > 0))) {
				next.ServeHTTP(w, r)
				return
			}

			primary := cacheKey(r)
			var vary []string
			if data := dc.getRaw(primary + "-vary"); data != nil {
				_ = json.Unmarshal(data, &vary)
			}
			key := variantKey(primary, r, vary, cfg)

			now := time.Now()
			old := dc.load(key)
			if old != nil {
				if now.Before(old.Expires) {
					writeEntry(w, old, "HIT")
					return
				}
				if now.Before(old.StaleUntil) {
					writeEntry(w, old, "STALE")
					dc.refreshAsync(next, r, cfg, key, primary, vary, old)
					return
				}
			}

			fetch := func() *fetched { return dc.fetchOrigin(next, r, cfg, primary, vary, old) }
			var f *fetched
			shared := false
			if cfg != nil && cfg.DisableCoalescing {
				f = fetch()
			} else {
				f, shared = dc.coalesce(r, key, primary, cfg, fetch)
			}

			if f.rec.code >= 500 && old != nil && now.Before(old.ErrorUntil) {
				writeEntry(w, old, "STALE")
				return
			}
			xc := "MISS"
			if shared {
				xc = "COALESCED"
			}
			writeRec(w, f.rec, xc)
		})
	}
}

type fetched struct {
	rec   *responseRecorder
	key   string   // clé sous laquelle la réponse est stockée ("" si non stockée)
	names []string // en-têtes Vary de la réponse
}

// fetchOrigin interroge le backend, puis stocke la réponse si elle est cacheable.
// old est l'entrée périmée éventuelle : une 5xx ne la remplace pas tant que sa
// fenêtre stale-if-error court.
func (dc *DiskCache) fetchOrigin(next http.Handler, r *http.Request, cfg *router.CacheConfig, primary string, vary []string, old *cacheEntry) *fetched {
	rec := &responseRecorder{code: http.StatusOK, headers: make(http.Header)}
	next.ServeHTTP(rec, r)
	f := &fetched{rec: rec}

	tags := extractTags(rec.headers)
	ttl := resolveTTL(rec.code, rec.headers, cfg)
	if ttl <= 0 || !responseCacheable(rec.headers) {
		return f
	}
	if rec.code >= 500 && old != nil && time.Now().Before(old.ErrorUntil) {
		return f
	}
	names, star := parseVary(rec.headers)
	if star {
		return f
	}
	key := variantKey(primary, r, vary, cfg)
	if len(names) > 0 || len(vary) > 0 {
		data, _ := json.Marshal(names)
		dc.setRaw(primary+"-vary", data)
		key = variantKey(primary, r, names, cfg)
	}

	cc := rec.headers.Get("Cache-Control")
	var swr, sie string
	if cfg != nil {
		swr, sie = cfg.StaleWhileRevalidate, cfg.StaleIfError
	}
	expires := time.Now().Add(ttl)
	dc.set(key, &cacheEntry{
		Status:     rec.code,
		Headers:    map[string][]string(rec.headers),
		Body:       rec.buf.Bytes(),
		Expires:    expires,
		StaleUntil: expires.Add(staleWindow(cc, "stale-while-revalidate", swr)),
		ErrorUntil: expires.Add(staleWindow(cc, "stale-if-error", sie)),
		Tags:       tags,
		URI:        r.URL.RequestURI(),
	})
	f.key, f.names = key, names
	return f
}

// coalesce exécute fn une seule fois pour les requêtes simultanées sur key. Un
// suiveur ne réutilise la réponse du meneur que si elle est stockée sous la clé
// qu'il aurait calculée lui-même (même variante) ; sinon il interroge le backend.
func (dc *DiskCache) coalesce(r *http.Request, key, primary string, cfg *router.CacheConfig, fn func() *fetched) (*fetched, bool) {
	dc.fmu.Lock()
	if fl, ok := dc.flights[key]; ok {
		dc.fmu.Unlock()
		select {
		case <-fl.done:
		case <-r.Context().Done():
			return &fetched{rec: &responseRecorder{code: http.StatusBadGateway, headers: make(http.Header)}}, false
		}
		if fl.res != nil && fl.res.key != "" && variantKey(primary, r, fl.res.names, cfg) == fl.res.key {
			return fl.res, true
		}
		return fn(), false
	}
	fl := &flight{done: make(chan struct{})}
	dc.flights[key] = fl
	dc.fmu.Unlock()

	defer func() {
		dc.fmu.Lock()
		delete(dc.flights, key)
		dc.fmu.Unlock()
		close(fl.done)
	}()
	fl.res = fn()
	return fl.res, false
}

// refreshAsync revalide une entrée servie périmée (stale-while-revalidate), une
// seule revalidation à la fois par clé.
func (dc *DiskCache) refreshAsync(next http.Handler, r *http.Request, cfg *router.CacheConfig, key, primary string, vary []string, old *cacheEntry) {
	dc.fmu.Lock()
	if dc.refreshing[key] {
		dc.fmu.Unlock()
		return
	}
	dc.refreshing[key] = true
	dc.fmu.Unlock()

	rr := r.Clone(context.WithoutCancel(r.Context()))
	go func() {
		defer func() {
			dc.fmu.Lock()
			delete(dc.refreshing, key)
			dc.fmu.Unlock()
		}()
		dc.fetchOrigin(next, rr, cfg, primary, vary, old)
	}()
}

func writeEntry(w http.ResponseWriter, e *cacheEntry, xcache string) {
	for name, vals := range e.Headers {
		for _, v := range vals {
			w.Header().Add(name, v)
		}
	}
	w.Header().Set("X-Cache", xcache)
	w.WriteHeader(e.Status)
	w.Write(e.Body) //nolint:errcheck
}

func writeRec(w http.ResponseWriter, rec *responseRecorder, xcache string) {
	for name, vals := range rec.headers {
		for _, v := range vals {
			w.Header().Add(name, v)
		}
	}
	w.Header().Set("X-Cache", xcache)
	w.WriteHeader(rec.code)
	w.Write(rec.buf.Bytes()) //nolint:errcheck
}

// isBypass retourne vrai si la requête doit contourner le cache.
func isBypass(r *http.Request, cfg *router.CacheConfig) bool {
	for _, h := range cfg.BypassHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	for _, name := range cfg.BypassCookies {
		if _, err := r.Cookie(name); err == nil {
			return true
		}
	}
	return false
}

// parseTTL convertit une string de durée humaine ("10m", "1h", "30s") en time.Duration.
func parseTTL(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d
	}
	// Accepter "10m30s" déjà géré par ParseDuration.
	// Essayer un entier seul (secondes).
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// resolveTTL détermine combien de temps mettre en cache la réponse.
// Ordre de priorité : CacheConfig.ValidRules > Cache-Control backend.
func resolveTTL(status int, headers http.Header, cfg *router.CacheConfig) time.Duration {
	// CacheConfig rules (proxy_cache_valid)
	if cfg != nil && len(cfg.ValidRules) > 0 {
		for _, rule := range cfg.ValidRules {
			if matchesRule(status, rule.StatusCodes) {
				return parseTTL(rule.TTL)
			}
		}
		// Si des règles sont définies mais aucune ne correspond, ne pas cacher.
		return 0
	}

	// Fallback legacy : max-age du backend
	cc := headers.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return 0
	}
	if maxAge := parseMaxAge(cc); maxAge > 0 {
		return time.Duration(maxAge) * time.Second
	}
	return 0
}

func matchesRule(status int, codes []int) bool {
	if len(codes) == 0 {
		return true // "any"
	}
	for _, c := range codes {
		if c == status {
			return true
		}
	}
	return false
}
