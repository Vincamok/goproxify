// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package fail2ban surveille le flux d'access logs de la passerelle et banne automatiquement
// les IPs abusives. Le moteur tourne entièrement dans la passerelle — indépendant de l'Admin.
package fail2ban

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Config paramètre le moteur Fail2Ban passerelle.
type Config struct {
	Enabled           bool     `json:"enabled"`
	WindowSec         int      `json:"window_sec"`          // fenêtre glissante (défaut 300)
	MaxErrors         int      `json:"max_errors"`          // seuil déclenchant le ban (défaut 50)
	BanDurationSec    int      `json:"ban_duration_sec"`    // 0 = permanent
	TrustForwardedFor bool     `json:"trust_forwarded_for"`
	Whitelist         []string `json:"whitelist"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		WindowSec:      300,
		MaxErrors:      50,
		BanDurationSec: 0,
	}
}

// Ban est un ban produit par le moteur.
type Ban struct {
	ID        string
	IP        string
	Reason    string
	ExpiresAt *time.Time // nil = permanent
}

// Engine maintient une fenêtre glissante d'erreurs par IP et crée des bans autonomes.
// Il est alimenté via Feed() depuis le middleware AccessLogger.
type Engine struct {
	mu  sync.RWMutex
	cfg Config

	// counters : ip → timestamps des requêtes 4xx (hors 404)
	counters map[string][]time.Time
	// banned : ips déjà bannies en mémoire (évite les doublons)
	banned map[string]struct{}

	bansMu  sync.RWMutex

	// OnBan est appelé dès qu'un nouveau ban est créé.
	// Le callback est responsable de persister et de notifier l'Admin.
	OnBan func(b Ban)

	lastBanMu sync.RWMutex
	lastBanAt time.Time

	stop chan struct{}
	done chan struct{}
}

// New crée un Engine. Appeler Start() pour lancer le nettoyage périodique.
func New() *Engine {
	return &Engine{
		cfg:      DefaultConfig(),
		counters: make(map[string][]time.Time),
		banned:   make(map[string]struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start lance la goroutine de nettoyage des compteurs expirés.
func (e *Engine) Start(_ context.Context) {
	go e.sweep()
}

// Stop arrête proprement le moteur.
func (e *Engine) Stop() {
	close(e.stop)
	<-e.done
}

// UpdateConfig remplace la configuration à chaud.
func (e *Engine) UpdateConfig(cfg Config) {
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// LastBan retourne l'heure du dernier ban déclenché (zéro si aucun).
func (e *Engine) LastBan() time.Time {
	e.lastBanMu.RLock()
	defer e.lastBanMu.RUnlock()
	return e.lastBanAt
}

// GetConfig retourne la config courante.
func (e *Engine) GetConfig() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Feed enregistre une requête. Appelé depuis le middleware AccessLogger pour chaque entrée.
// status et ip sont extraits du log d'accès.
func (e *Engine) Feed(ip string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	if !cfg.Enabled {
		return
	}
	// Seules les erreurs 4xx hors 404 comptent (abus client, pas erreurs légitimes).
	if status < 400 || status >= 500 || status == 404 {
		return
	}

	addr, ok := clientAddr(ip)
	if !ok || isPrivateIP(addr) || whitelisted(netip.PrefixFrom(addr, addr.BitLen()), cfg.Whitelist) {
		return
	}
	key := banKey(addr, cfg.Whitelist)

	window := time.Duration(cfg.WindowSec) * time.Second
	if window <= 0 {
		window = 300 * time.Second
	}
	maxErr := cfg.MaxErrors
	if maxErr <= 0 {
		maxErr = 50
	}

	now := time.Now()
	cutoff := now.Add(-window)

	e.mu.Lock()
	// Nettoyage de la fenêtre pour cette IP.
	ts := e.counters[key]
	filtered := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	e.counters[key] = filtered
	count := len(filtered)
	e.mu.Unlock()

	if count < maxErr {
		return
	}

	// Vérification doublon en mémoire.
	e.bansMu.RLock()
	_, already := e.banned[key]
	e.bansMu.RUnlock()
	if already {
		return
	}

	e.bansMu.Lock()
	e.banned[key] = struct{}{}
	e.mu.Lock()
	delete(e.counters, key)
	e.mu.Unlock()
	e.bansMu.Unlock()

	ban := Ban{
		ID:     uuid.New().String(),
		IP:     key,
		Reason: "Fail2Ban: trop d'erreurs",
	}
	if cfg.BanDurationSec > 0 {
		exp := now.Add(time.Duration(cfg.BanDurationSec) * time.Second)
		ban.ExpiresAt = &exp
	}

	e.lastBanMu.Lock()
	e.lastBanAt = time.Now()
	e.lastBanMu.Unlock()
	if e.OnBan != nil {
		e.OnBan(ban)
	}
}

// UnbanIP oublie l'IP (suite à un unban Admin) : elle peut de nouveau être bannie, à partir d'un compteur vide.
func (e *Engine) UnbanIP(ip string) {
	e.bansMu.Lock()
	delete(e.banned, ip)
	e.bansMu.Unlock()
	e.mu.Lock()
	delete(e.counters, ip)
	e.mu.Unlock()
}

// Whitelisted indique si la cible d'un ban (IP ou CIDR) recoupe la liste blanche courante.
func (e *Engine) Whitelisted(ip string) bool {
	p, ok := toPrefix(ip)
	return ok && whitelisted(p, e.GetConfig().Whitelist)
}

// sweep nettoie périodiquement les compteurs pour les IPs inactives.
func (e *Engine) sweep() {
	defer close(e.done)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.mu.RLock()
			cfg := e.cfg
			e.mu.RUnlock()
			window := time.Duration(cfg.WindowSec) * time.Second
			if window <= 0 {
				window = 300 * time.Second
			}
			cutoff := time.Now().Add(-window)

			e.mu.Lock()
			for ip, ts := range e.counters {
				filtered := ts[:0]
				for _, t := range ts {
					if t.After(cutoff) {
						filtered = append(filtered, t)
					}
				}
				if len(filtered) == 0 {
					delete(e.counters, ip)
				} else {
					e.counters[ip] = filtered
				}
			}
			e.mu.Unlock()
		}
	}
}

// clientAddr lit une IP seule, « IP:port » ou « [IPv6]:port ». Faux pour tout ce qui n'est pas une IP.
func clientAddr(s string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// toPrefix lit une IP (préfixe /32 ou /128) ou un CIDR.
func toPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	a, ok := clientAddr(s)
	return netip.PrefixFrom(a, a.BitLen()), ok
}

// banKey est la clé de comptage et la cible du ban : l'adresse pour une IPv4, son /64 pour une IPv6
// (même agrégation que les compteurs Sentinel). Un /64 revient en général à un seul abonné, qui y
// change d'adresse à volonté : compté adresse par adresse, il resterait toujours sous le seuil.
// Si la liste blanche recoupe le /64, on s'en tient à l'adresse pour ne pas bloquer l'IP exemptée.
func banKey(a netip.Addr, whitelist []string) string {
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	if whitelisted(p, whitelist) {
		return a.String()
	}
	return p.String()
}

// whitelisted indique si p recoupe une entrée de la liste blanche (IP ou CIDR).
func whitelisted(p netip.Prefix, whitelist []string) bool {
	for _, entry := range whitelist {
		if w, ok := toPrefix(entry); ok && w.Overlaps(p) {
			return true
		}
	}
	return false
}

// cloudflareRanges : ces IPs portent le trafic de tous les utilisateurs finaux
// quand Cloudflare est en amont — ne jamais bannir.
var cloudflareRanges = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
	"188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var exemptNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, cidr := range append([]string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}, cloudflareRanges...) {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}()

func isPrivateIP(a netip.Addr) bool {
	for _, p := range exemptNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- Persistance de la config sur le volume passerelle ---

const (
	defaultCfgDir  = "/etc/goproxify/fail2ban"
	cfgFileName    = "config.json"
	envCfgPathKey  = "GPX_F2B_CONFIG_PATH"
)

// CfgDir retourne le répertoire de configuration (env GPX_F2B_CONFIG_PATH ou défaut).
func CfgDir() string {
	if p := os.Getenv(envCfgPathKey); p != "" {
		return p
	}
	return defaultCfgDir
}

// LoadConfig lit la config depuis le disque. Retourne DefaultConfig() si absent.
func LoadConfig(dir string) Config {
	if dir == "" {
		dir = CfgDir()
	}
	data, err := os.ReadFile(filepath.Join(dir, cfgFileName))
	if err != nil {
		return DefaultConfig()
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		return DefaultConfig()
	}
	return cfg
}

// SaveConfig persiste la config sur le disque (atomic write).
func SaveConfig(dir string, cfg Config) error {
	if dir == "" {
		dir = CfgDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "f2b-cfg-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Close()
	return os.Rename(tmpName, filepath.Join(dir, cfgFileName))
}

// HasConfig indique si l ancien fichier de configuration en clair existe.
func HasConfig(dir string) bool {
	if dir == "" {
		dir = CfgDir()
	}
	_, err := os.Stat(filepath.Join(dir, cfgFileName))
	return err == nil
}

// RemoveConfig supprime l ancien fichier de configuration en clair.
func RemoveConfig(dir string) error {
	if dir == "" {
		dir = CfgDir()
	}
	err := os.Remove(filepath.Join(dir, cfgFileName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
