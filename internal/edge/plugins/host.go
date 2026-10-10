// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// Capacités optionnelles (ADR 0008). Un plugin n'a aucune capacité par défaut : celles qu'il déclare dans son
// manifeste sont les seules fonctions de l'hôte qu'il peut importer, et le chargement refuse un import non
// déclaré.
//
//	gpx.log(ptr, len)                                  toujours disponible
//	gpx.kv_get(kptr, klen) -> i64                      capacité « kv » : -1 si absent, sinon ptr<<32 | len
//	gpx.kv_set(kptr, klen, vptr, vlen, ttl_ms) -> i32  0 ok, 1 quota atteint, 2 arguments invalides
//	gpx.kv_incr(kptr, klen, delta i64, ttl_ms) -> i64  nouvelle valeur, ou math.MinInt64 en cas d'erreur
//	gpx.http_fetch(ptr, len) -> i64                    capacité « http » : ptr<<32 | len d'une réponse JSON
const (
	// Bornes de l'état (kv) : un plugin ne peut pas faire grossir la mémoire de la passerelle sans limite.
	kvMaxKeys     = 1024
	kvMaxKeyBytes = 128
	kvMaxValBytes = 4 << 10
	kvDefaultTTL  = time.Hour
	kvMaxTTL      = 24 * time.Hour

	// Bornes du réseau (http).
	fetchMaxPerCall   = 3
	fetchMaxBodyBytes = 64 << 10
	fetchMaxTimeout   = 2 * time.Second

	kvErrIncr = int64(-1 << 63)
)

// Capabilities déclare ce qu'un plugin a le droit d'utiliser en plus de gpx.log.
type Capabilities struct {
	// KV : état clé/valeur borné, propre au plugin, en mémoire de la passerelle (perdu au redémarrage et au
	// remplacement du plugin).
	KV bool `json:"kv,omitempty"`
	// HTTP : noms d'hôtes joignables par gpx.http_fetch (exacts, ou « *.exemple.fr » pour les sous-domaines).
	HTTP []string `json:"http,omitempty"`
	// HTTPAllowPrivate lève l'interdiction des adresses privées, loopback et link-local (métadonnées cloud
	// comprises) : à n'activer que pour joindre un service interne connu.
	HTTPAllowPrivate bool `json:"http_allow_private,omitempty"`
}

func (c *Capabilities) validate() error {
	if c == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, h := range c.HTTP {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.ContainsAny(h, "/:@ ") || h == "*" || strings.Count(h, "*") > 1 || (strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
			return fmt.Errorf("capabilities.http : %q invalide (nom d'hôte exact ou « *.exemple.fr »)", h)
		}
		if seen[h] {
			return fmt.Errorf("capabilities.http : %q en double", h)
		}
		seen[h] = true
	}
	if c.HTTPAllowPrivate && len(c.HTTP) == 0 {
		return errors.New("capabilities.http_allow_private sans capabilities.http")
	}
	return nil
}

func (c *Capabilities) allowsHost(host string) bool {
	if c == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range c.HTTP {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == host {
			return true
		}
		if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && len(host) > len(h)-1 {
			return true
		}
	}
	return false
}

// ── état de l'appel ──────────────────────────────────────────────────────────────────────────────────

type stateKey struct{}

// callState est l'état d'un appel de hook, passé aux fonctions hôtes par le contexte.
type callState struct {
	p       *Plugin
	logs    logCollector
	fetches int
}

func stateOf(ctx context.Context) *callState {
	s, _ := ctx.Value(stateKey{}).(*callState)
	return s
}

// ── mémoire du plugin ────────────────────────────────────────────────────────────────────────────────

func guestRead(m api.Module, ptr, n, max uint32) ([]byte, bool) {
	if n > max {
		return nil, false
	}
	b, ok := m.Memory().Read(ptr, n)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true // copie : la mémoire du plugin peut changer pendant l'appel
}

// guestWrite copie data dans la mémoire du plugin (via son export alloc) et retourne ptr<<32 | len.
func guestWrite(ctx context.Context, m api.Module, data []byte) (uint64, bool) {
	if len(data) == 0 {
		return 0, true
	}
	res, err := m.ExportedFunction("alloc").Call(ctx, uint64(len(data)))
	if err != nil || len(res) != 1 {
		return 0, false
	}
	ptr := uint32(res[0])
	if !m.Memory().Write(ptr, data) {
		return 0, false
	}
	return uint64(ptr)<<32 | uint64(len(data)), true
}

// ── état clé/valeur ──────────────────────────────────────────────────────────────────────────────────

type kvEntry struct {
	val     []byte
	num     int64
	numeric bool
	expires time.Time
}

type kvStore struct {
	mu   sync.Mutex
	m    map[string]*kvEntry
	nowF func() time.Time
}

func newKV() *kvStore { return &kvStore{m: map[string]*kvEntry{}, nowF: time.Now} }

func (k *kvStore) purgeLocked(now time.Time) {
	for key, e := range k.m {
		if !e.expires.After(now) {
			delete(k.m, key)
		}
	}
}

func ttlOf(ms uint32) time.Duration {
	d := time.Duration(ms) * time.Millisecond
	if d <= 0 {
		return kvDefaultTTL
	}
	return min(d, kvMaxTTL)
}

func (k *kvStore) get(key string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.m[key]
	if !ok || !e.expires.After(k.nowF()) {
		delete(k.m, key)
		return nil, false
	}
	if e.numeric {
		return []byte(strconv.FormatInt(e.num, 10)), true
	}
	return e.val, true
}

// set retourne 0 (ok) ou 1 (quota atteint).
func (k *kvStore) set(key string, val []byte, ttl time.Duration) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.nowF()
	if _, exists := k.m[key]; !exists && len(k.m) >= kvMaxKeys {
		k.purgeLocked(now)
		if len(k.m) >= kvMaxKeys {
			return 1
		}
	}
	k.m[key] = &kvEntry{val: val, expires: now.Add(ttl)}
	return 0
}

// incr ajoute delta à un compteur (créé à 0, avec ttl, s'il n'existe pas ; le délai n'est pas prolongé par les
// incrémentations suivantes : fenêtre fixe, utile pour une limitation de débit).
func (k *kvStore) incr(key string, delta int64, ttl time.Duration) (int64, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.nowF()
	e, ok := k.m[key]
	if ok && !e.expires.After(now) {
		delete(k.m, key)
		ok = false
	}
	if !ok {
		if len(k.m) >= kvMaxKeys {
			k.purgeLocked(now)
			if len(k.m) >= kvMaxKeys {
				return 0, false
			}
		}
		e = &kvEntry{numeric: true, expires: now.Add(ttl)}
		k.m[key] = e
	}
	if !e.numeric {
		return 0, false
	}
	e.num += delta
	return e.num, true
}

func (p *Plugin) hostKVGet(ctx context.Context, m api.Module, kptr, klen uint32) uint64 {
	const missing = ^uint64(0)
	st := stateOf(ctx)
	if st == nil || p.kv == nil {
		return missing
	}
	key, ok := guestRead(m, kptr, klen, kvMaxKeyBytes)
	if !ok || len(key) == 0 {
		return missing
	}
	val, found := p.kv.get(string(key))
	if !found {
		return missing
	}
	if len(val) == 0 {
		return 0 // présent mais vide : ptr et longueur nuls (distinct de « absent »)
	}
	packed, ok := guestWrite(ctx, m, val)
	if !ok {
		return missing
	}
	return packed
}

func (p *Plugin) hostKVSet(ctx context.Context, m api.Module, kptr, klen, vptr, vlen, ttlMs uint32) uint32 {
	if stateOf(ctx) == nil || p.kv == nil {
		return 2
	}
	key, ok := guestRead(m, kptr, klen, kvMaxKeyBytes)
	if !ok || len(key) == 0 {
		return 2
	}
	val, ok := guestRead(m, vptr, vlen, kvMaxValBytes)
	if !ok {
		return 2
	}
	return p.kv.set(string(key), val, ttlOf(ttlMs))
}

func (p *Plugin) hostKVIncr(ctx context.Context, m api.Module, kptr, klen uint32, delta int64, ttlMs uint32) int64 {
	if stateOf(ctx) == nil || p.kv == nil {
		return kvErrIncr
	}
	key, ok := guestRead(m, kptr, klen, kvMaxKeyBytes)
	if !ok || len(key) == 0 {
		return kvErrIncr
	}
	n, ok := p.kv.incr(string(key), delta, ttlOf(ttlMs))
	if !ok {
		return kvErrIncr
	}
	return n
}

// ── réseau ───────────────────────────────────────────────────────────────────────────────────────────

type fetchRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      []byte            `json:"body,omitempty"` // base64 en JSON
	TimeoutMs int               `json:"timeout_ms,omitempty"`
}

type fetchResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// blockedIP : adresses que gpx.http_fetch refuse sauf http_allow_private (SSRF : métadonnées cloud, réseau
// interne, boucle locale).
func blockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 { // 100.64.0.0/10 (CGNAT)
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()
}

// fetchClient : client HTTP d'un plugin (voir SafeHTTPClient).
func (p *Plugin) fetchClient(timeout time.Duration) *http.Client {
	return SafeHTTPClient(timeout, p.Manifest.Capabilities.private())
}

// SafeHTTPClient : client HTTP pour joindre une adresse choisie par un tiers (plugin, dépôt de plugins) — pas de
// redirection, pas de proxy d'environnement, et refus de l'adresse *résolue* si elle est interne sauf
// allowPrivate (le contrôle a lieu à la connexion, ce qui déjoue le rebinding DNS).
func SafeHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip != nil && blockedIP(ip) && !allowPrivate {
				return fmt.Errorf("adresse %s refusée (réseau interne)", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// BlockedHost indique si une adresse IP littérale est interne (boucle locale, privée, link-local, métadonnées).
func BlockedHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && blockedIP(ip)
}

func (p *Plugin) doFetch(ctx context.Context, req fetchRequest) fetchResponse {
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fetchResponse{Error: "URL invalide (http ou https attendu)"}
	}
	if !p.Manifest.Capabilities.allowsHost(u.Hostname()) {
		return fetchResponse{Error: "hôte non autorisé par le manifeste : " + u.Hostname()}
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && blockedIP(ip) && !p.Manifest.Capabilities.private() {
		return fetchResponse{Error: "adresse refusée (réseau interne)"}
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return fetchResponse{Error: "méthode refusée : " + method}
	}
	timeout := fetchMaxTimeout
	if req.TimeoutMs > 0 {
		timeout = min(time.Duration(req.TimeoutMs)*time.Millisecond, fetchMaxTimeout)
	}
	if dl, ok := ctx.Deadline(); ok {
		// 80 % du temps restant : le plugin doit pouvoir recevoir l'échec et répondre avant que l'appel
		// entier soit interrompu par son propre délai.
		if left := time.Until(dl) * 8 / 10; left < timeout {
			timeout = left
		}
	}
	if timeout <= 0 {
		return fetchResponse{Error: "délai de l'appel épuisé"}
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, strings.NewReader(string(req.Body)))
	if err != nil {
		return fetchResponse{Error: err.Error()}
	}
	for k, v := range req.Headers {
		if !validHeaderName(k) || !validHeaderValue(v) {
			return fetchResponse{Error: "en-tête refusé : " + k}
		}
		hreq.Header.Set(k, v)
	}
	resp, err := p.fetchClient(timeout).Do(hreq)
	if err != nil {
		return fetchResponse{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchMaxBodyBytes+1))
	if err != nil {
		return fetchResponse{Status: resp.StatusCode, Error: err.Error()}
	}
	out := fetchResponse{Status: resp.StatusCode, Headers: map[string]string{}}
	if len(body) > fetchMaxBodyBytes {
		body = body[:fetchMaxBodyBytes]
		out.Error = "réponse tronquée à " + strconv.Itoa(fetchMaxBodyBytes) + " octets"
	}
	out.Body = body
	for k := range resp.Header {
		out.Headers[k] = resp.Header.Get(k)
	}
	return out
}

func (p *Plugin) hostHTTPFetch(ctx context.Context, m api.Module, ptr, n uint32) uint64 {
	reply := func(r fetchResponse) uint64 {
		b, _ := json.Marshal(r)
		packed, ok := guestWrite(ctx, m, b)
		if !ok {
			return 0
		}
		return packed
	}
	st := stateOf(ctx)
	if st == nil || len(p.Manifest.Capabilities.httpHosts()) == 0 {
		return reply(fetchResponse{Error: "capacité http non déclarée"})
	}
	if st.fetches >= fetchMaxPerCall {
		return reply(fetchResponse{Error: "trop d'appels réseau dans ce hook"})
	}
	st.fetches++
	raw, ok := guestRead(m, ptr, n, MaxIOBytes)
	if !ok {
		return reply(fetchResponse{Error: "requête illisible"})
	}
	var req fetchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return reply(fetchResponse{Error: "requête illisible : " + err.Error()})
	}
	return reply(p.doFetch(ctx, req))
}

func (c *Capabilities) httpHosts() []string {
	if c == nil {
		return nil
	}
	return c.HTTP
}

func (c *Capabilities) private() bool { return c != nil && c.HTTPAllowPrivate }

// SafeHTTPClientFollow : comme SafeHTTPClient mais suit jusqu'à 3 redirections (les dépôts de plugins sont
// souvent derrière un CDN ou des « releases »). Chaque connexion est contrôlée à nouveau par le dialer, et une
// redirection vers du HTTP clair est refusée sauf allowPrivate.
func SafeHTTPClientFollow(timeout time.Duration, allowPrivate bool) *http.Client {
	c := SafeHTTPClient(timeout, allowPrivate)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("trop de redirections")
		}
		if req.URL.Scheme != "https" && !allowPrivate {
			return errors.New("redirection vers un schéma non sécurisé refusée")
		}
		return nil
	}
	return c
}
