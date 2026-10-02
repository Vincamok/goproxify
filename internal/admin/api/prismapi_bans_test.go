package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// L'interface masque Bannir pour une IP tronquée par l'anonymisation : top IPs et analyse d'IP
// doivent le signaler.
func TestPrismFlagsTruncatedIPs(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	for ip, truncated := range map[string]int{"203.0.113.0": 1, "198.51.100.7": 0} {
		if _, err := db.Exec(`INSERT INTO logs (ts, domain, ip, status, ip_truncated) VALUES (?, 'api.acme.fr', ?, 403, ?)`, at, ip, truncated); err != nil {
			t.Fatal(err)
		}
	}
	h := &PrismHandler{DB: db}
	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : status %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}

	var ips []struct {
		IP          string `json:"ip"`
		IPTruncated bool   `json:"ip_truncated"`
	}
	get("/api/v1/prism/ips", &ips)
	if len(ips) != 2 {
		t.Fatalf("/prism/ips = %+v, attendu 2 IP", ips)
	}
	for _, e := range ips {
		if e.IPTruncated != (e.IP == "203.0.113.0") {
			t.Errorf("/prism/ips %s : ip_truncated = %v", e.IP, e.IPTruncated)
		}
	}
	for ip, want := range map[string]bool{"203.0.113.0": true, "198.51.100.7": false} {
		var scan struct {
			Requests    int  `json:"requests"`
			IPTruncated bool `json:"ip_truncated"`
		}
		get("/api/v1/prism/ip-scan?ip="+ip, &scan)
		if scan.Requests != 1 || scan.IPTruncated != want {
			t.Errorf("/prism/ip-scan %s = %+v, attendu 1 requête, ip_truncated=%v", ip, scan, want)
		}
	}
}

func TestBanTechnique(t *testing.T) {
	cases := []struct{ src, reason, key, label string }{
		{"threat", "threat: path", "path", "Chemin sensible (scan)"},
		{"threat", "threat: rate", "rate", "Débit excessif"},
		{"fail2ban", "Fail2Ban: trop d'erreurs", "errors", "Trop d'erreurs HTTP"},
		{"crowdsec", "crowdsecurity/http-probing", "crowdsecurity/http-probing", "crowdsecurity/http-probing"},
		{"native", "", "unknown", "Non précisé"},
	}
	for _, c := range cases {
		k, l := banTechnique(c.src, c.reason)
		if k != c.key || l != c.label {
			t.Errorf("%s/%q = %q,%q ; attendu %q,%q", c.src, c.reason, k, l, c.key, c.label)
		}
	}
}
