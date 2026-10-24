// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoEntry répartition du trafic par pays.
type GeoEntry struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Requests    int64   `json:"requests"`
	Pct         float64 `json:"pct"`
	Errors      int64   `json:"errors"`
	ErrorRate   float64 `json:"error_rate"`
	BannedIPs   int64   `json:"banned_ips"`
}

// GeoResolver résout les IPs en pays via ip-api.com et met en cache dans SQLite.
type GeoResolver struct {
	DB  *sql.DB
	Log *slog.Logger
	// MMDBPath : base GeoLite2-City locale. Présente, elle remplace ip-api.com (aucune IP ne sort) ;
	// absente ou illisible, on ne retombe sur ip-api.com que si AllowExternal est vrai.
	MMDBPath string
	// AllowExternal autorise l'envoi des IP à ip-api.com faute de base locale (tiers, HTTP : RGPD).
	AllowExternal bool

	mu     sync.Mutex
	reader *maxminddb.Reader
}

type ipAPIResult struct {
	Query       string  `json:"query"`
	CountryCode string  `json:"countryCode"`
	Country     string  `json:"country"`
	Status      string  `json:"status"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city"`
	RegionName  string  `json:"regionName"`
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, network)
		}
	}
}

type mmdbCity struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// local retourne la base GeoLite2-City si elle est disponible (ouverte au premier usage, elle peut arriver après le démarrage).
func (g *GeoResolver) local() *maxminddb.Reader {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reader == nil && g.MMDBPath != "" {
		if r, err := maxminddb.Open(g.MMDBPath); err == nil {
			g.reader = r
			g.log().Info("geoip: base locale GeoLite2-City utilisée", "path", g.MMDBPath)
		}
	}
	return g.reader
}

func lookupLocal(r *maxminddb.Reader, ip string) ipAPIResult {
	res := ipAPIResult{Query: ip, Status: "fail"}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return res
	}
	var rec mmdbCity
	if err := r.Lookup(parsed, &rec); err != nil || rec.Country.ISOCode == "" {
		return res
	}
	res.Status, res.CountryCode, res.Country = "success", rec.Country.ISOCode, rec.Country.Names["en"]
	res.City, res.Lat, res.Lon = rec.City.Names["en"], rec.Location.Latitude, rec.Location.Longitude
	if len(rec.Subdivisions) > 0 {
		res.RegionName = rec.Subdivisions[0].Names["en"]
	}
	return res
}

// ErrExternalLookupDisabled : pas de base locale et le repli sur ip-api.com n'est pas autorisé.
var ErrExternalLookupDisabled = errors.New("geoip: base locale absente et repli ip-api.com non autorisé")

// lookup résout des IPs : base locale si présente, sinon ip-api.com si autorisé.
func (g *GeoResolver) lookup(ctx context.Context, ips []string) ([]ipAPIResult, error) {
	if r := g.local(); r != nil {
		out := make([]ipAPIResult, len(ips))
		for i, ip := range ips {
			out[i] = lookupLocal(r, ip)
		}
		return out, nil
	}
	if !g.AllowExternal {
		return nil, ErrExternalLookupDisabled
	}
	return g.lookupBatch(ctx, ips)
}

// Start complète en arrière-plan, toutes les 60 secondes, la position des entrées du cache qui n'en ont pas encore. Les
// IP nouvelles ne sont plus découvertes dans des lignes d'accès (l'Admin n'en reçoit plus) : elles sont résolues à la
// demande (Ensure) quand une liste ou la carte les affiche.
func (g *GeoResolver) Start(ctx context.Context) {
	go func() {
		g.backfillPositions(ctx)
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.backfillPositions(ctx)
			}
		}
	}()
}

// normalizeIP extrait l'adresse IP d'une valeur logs.ip (IPv4, IPv4:port, IPv6, [IPv6]:port).
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	// IPv6 sans port (contient ':') ou IPv4 nue.
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	// Fallback : strip host:port IPv4 naïf.
	if i := strings.LastIndex(raw, ":"); i > 0 && strings.Count(raw, ":") == 1 {
		if ip := net.ParseIP(raw[:i]); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func isPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, network := range privateNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// batchLimit : 100 IPs par minute avec ip-api.com (quota gratuit), bien plus avec une base locale.
func (g *GeoResolver) batchLimit() int {
	if g.local() != nil {
		return 5000
	}
	return 100
}

func (g *GeoResolver) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

func (g *GeoResolver) cacheEntry(ip, cc, cn string) {
	_, _ = g.DB.Exec(
		`INSERT OR IGNORE INTO geoip_cache (ip, country_code, country_name) VALUES (?,?,?)`,
		ip, cc, cn)
}

// cacheResult enregistre pays et position ; ne remplace pas une entrée existante.
func (g *GeoResolver) cacheResult(ip string, r ipAPIResult) {
	if r.Status != "success" || r.CountryCode == "" {
		g.cacheEntry(ip, "XX", "Unknown")
		return
	}
	_, _ = g.DB.Exec(
		`INSERT OR IGNORE INTO geoip_cache (ip, country_code, country_name, lat, lon, city, region) VALUES (?,?,?,?,?,?,?)`,
		ip, r.CountryCode, r.Country, r.Lat, r.Lon, r.City, r.RegionName)
}

// lookupBatch interroge ip-api.com (HTTP gratuit, ≤100 IPs, 45 req/min).
// Aucune écriture : l'appelant décide quoi cacher en cas d'échec.
func (g *GeoResolver) lookupBatch(ctx context.Context, ips []string) ([]ipAPIResult, error) {
	payload := make([]map[string]string, len(ips))
	for i, ip := range ips {
		payload[i] = map[string]string{"query": ip}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://ip-api.com/batch?fields=query,countryCode,country,status,lat,lon,city,regionName", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api.com status %d", resp.StatusCode)
	}
	var results []ipAPIResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	return results, nil
}

// backfillPositions complète lat/lon/ville des entrées créées avant la carte détaillée.
func (g *GeoResolver) backfillPositions(ctx context.Context) {
	rows, err := g.DB.QueryContext(ctx,
		`SELECT ip FROM geoip_cache
		 WHERE lat IS NULL AND country_code NOT IN ('LO','XX','')
		 LIMIT ?`, g.batchLimit())
	if err != nil {
		return
	}
	byQuery := map[string][]string{}
	var queries, unusable []string
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		q := normalizeIP(raw)
		if q == "" || isPrivate(q) {
			unusable = append(unusable, raw)
			continue
		}
		if _, ok := byQuery[q]; !ok {
			queries = append(queries, q)
		}
		byQuery[q] = append(byQuery[q], raw)
	}
	rows.Close()
	// (0,0) = position inconnue : exclue de la carte, plus jamais ré-interrogée.
	for _, raw := range unusable {
		_, _ = g.DB.Exec(`UPDATE geoip_cache SET lat=0, lon=0 WHERE ip=?`, raw)
	}
	if len(queries) == 0 {
		return
	}
	results, err := g.lookup(ctx, queries)
	if errors.Is(err, ErrExternalLookupDisabled) {
		return
	}
	if err != nil {
		g.log().Warn("geoip: complément de positions échoué (réessai au prochain cycle)", "err", err)
		return
	}
	for _, r := range results {
		lat, lon := r.Lat, r.Lon
		if r.Status != "success" {
			lat, lon = 0, 0
		}
		for _, raw := range byQuery[r.Query] {
			_, _ = g.DB.Exec(`UPDATE geoip_cache SET lat=?, lon=?, city=?, region=? WHERE ip=?`,
				lat, lon, r.City, r.RegionName, raw)
		}
	}
}

// LiveIPEvent représente un événement IP récent pour la vue live de la carte.
type LiveIPEvent struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Kind        string `json:"kind"` // "visit" | "error" | "banned"
	Status      int    `json:"status"`
	Domain      string `json:"domain"`
	Ts          string `json:"ts"`
	// Position approximative (ville) ; 0/0 tant que l'IP n'est pas localisée.
	City string  `json:"city"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
}

// GeoPoint agrège le trafic d'une ville (position approximative issue de la géolocalisation IP).
type GeoPoint struct {
	City        string  `json:"city"`
	Region      string  `json:"region"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Requests    int64   `json:"requests"`
	Errors      int64   `json:"errors"`
	ErrorRate   float64 `json:"error_rate"`
	IPs         int64   `json:"ips"`
	BannedIPs   int64   `json:"banned_ips"`
}

// activeBannedIPSet retourne l'ensemble des IPs actives dans security_bans.
func activeBannedIPSet(db *sql.DB) map[string]bool {
	rows, err := db.Query(
		`SELECT ip FROM security_bans
		 WHERE expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		m[ip] = true
	}
	return m
}

// geoBannedIPs retourne le nombre d'IPs bannies actives par country_code.
func geoBannedIPs(db *sql.DB) map[string]int64 {
	rows, err := db.Query(
		`SELECT COALESCE(g.country_code,'?') as cc, COUNT(DISTINCT sb.ip)
		 FROM security_bans sb
		 LEFT JOIN geoip_cache g ON g.ip = sb.ip
		 WHERE (sb.expires_at IS NULL OR datetime(sb.expires_at) > CURRENT_TIMESTAMP)
		 GROUP BY cc`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var cc string
		var n int64
		_ = rows.Scan(&cc, &n)
		m[cc] = n
	}
	return m
}

// Ensure géolocalise les IP de la liste qui n'ont pas encore d'entrée dans le cache, sans attendre le passage de
// fond : les lignes de logs n'arrivent plus à l'Admin, ce sont les listes qu'il affiche qui disent quelles IP
// résoudre (ADR 0012). Au plus batchLimit adresses par appel ; les autres viendront aux appels suivants.
func (g *GeoResolver) Ensure(ctx context.Context, ips []string) {
	const chunk = 500
	var missing []string
	for start := 0; start < len(ips); start += chunk {
		part := ips[start:min(start+chunk, len(ips))]
		args := make([]any, len(part))
		for i, ip := range part {
			args[i] = ip
		}
		rows, err := g.DB.QueryContext(ctx, `SELECT ip FROM geoip_cache WHERE ip IN (?`+strings.Repeat(",?", len(part)-1)+`)`, args...)
		if err != nil {
			return
		}
		known := map[string]bool{}
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				known[ip] = true
			}
		}
		rows.Close()
		for _, ip := range part {
			if ip != "" && !known[ip] {
				missing = append(missing, ip)
			}
		}
	}
	limit := g.batchLimit()
	queryToLog := map[string][]string{}
	var queries []string
	for _, raw := range missing {
		q := normalizeIP(raw)
		if q == "" || isPrivate(q) {
			g.cacheEntry(raw, "LO", "Local / Private")
			continue
		}
		if _, seen := queryToLog[q]; !seen {
			if len(queries) >= limit {
				continue
			}
			queries = append(queries, q)
		}
		queryToLog[q] = append(queryToLog[q], raw)
	}
	if len(queries) == 0 {
		return
	}
	results, err := g.lookup(ctx, queries)
	if err != nil {
		return
	}
	for _, r := range results {
		logIPs := queryToLog[r.Query]
		if len(logIPs) == 0 {
			logIPs = queryToLog[normalizeIP(r.Query)]
		}
		for _, ip := range logIPs {
			g.cacheResult(ip, r)
		}
	}
}
