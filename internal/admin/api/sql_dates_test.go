// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rulesengine"
	"github.com/vincamok/goproxify/internal/sqltime"
)

func openSQLDatesDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// withLocalZone simule un processus lancé avec TZ≠UTC (TZ=Europe/Paris par défaut en déploiement).
func withLocalZone(t *testing.T, offsetHours int) {
	t.Helper()
	prev := time.Local
	time.Local = time.FixedZone("TEST", offsetHours*3600)
	t.Cleanup(func() { time.Local = prev })
}

func serve(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if s, ok := body.(string); ok {
		buf.WriteString(s)
	} else if body != nil {
		json.NewEncoder(&buf).Encode(body) //nolint:errcheck
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	return rec
}

func selfSignedCertPEM(t *testing.T, domain string, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestImportedCertIsSeenByCertExpiringRule(t *testing.T) {
	db := openSQLDatesDB(t)
	certPEM, keyPEM := selfSignedCertPEM(t, "import.example.com", time.Now().Add(10*24*time.Hour))
	if rec := serve(t, &CertsHandler{DB: db, Log: slog.Default()}, http.MethodPost, "/api/v1/certs/import",
		map[string]string{"cert_pem": certPEM, "key_pem": keyPEM}); rec.Code != http.StatusCreated {
		t.Fatalf("import : status %d %s", rec.Code, rec.Body)
	}
	// La règle lit expires_at via julianday(), qui renvoie NULL pour un time.Time lié tel quel (t.String()).
	matched, detail, err := rulesengine.New(db, slog.Default(), rulesengine.Deps{}).EvalCondition(context.Background(),
		rulesengine.Condition{Type: rulesengine.CondCertExpiring, DaysLeft: 15})
	if err != nil || !matched || detail["domain"] != "import.example.com" {
		t.Fatalf("cert_expiring (15 j) doit voir le certificat importé qui expire dans 10 j : %v %v %v", matched, detail, err)
	}
}

func TestSilencesApplyWhateverTheClientOffset(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cond, _ := json.Marshal(rulesengine.Condition{Type: rulesengine.CondBanSpike, BanCount: 1, BanWindow: "1h"})
	if _, err := db.Exec(`INSERT INTO rules_engine_rules (id, name, enabled, condition_json, action_json) VALUES ('r1', 'pic', 1, ?, '{"type":"notify"}')`, string(cond)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO security_bans (id, ip, source) VALUES ('b1', '203.0.113.40', 'fail2ban')`); err != nil {
		t.Fatal(err)
	}
	h := &RulesEngineHandler{DB: db, Log: slog.Default()}
	// Client à UTC-5 : l'ancien stockage « 2026-10-01 05:59:00 -0500 -0500 » était illisible et comparé
	// en texte à l'heure UTC, le silence était ignoré.
	ny := time.FixedZone("", -5*3600)
	if rec := serve(t, h, http.MethodPost, "/api/v1/rules-engine/silences", map[string]any{
		"name": "maintenance", "rule_ids": []string{"r1"},
		"starts_at": time.Now().Add(-time.Minute).In(ny).Format(time.RFC3339),
		"ends_at":   time.Now().Add(time.Hour).In(ny).Format(time.RFC3339),
	}); rec.Code != http.StatusCreated {
		t.Fatalf("création du silence : status %d %s", rec.Code, rec.Body)
	}
	matched, detail, err := rulesengine.New(db, slog.Default(), rulesengine.Deps{}).EvalNow(context.Background(), "r1", true)
	if err != nil || !matched || detail["silenced"] != true {
		t.Fatalf("la règle déclenchée doit être silencée : %v %v %v", matched, detail, err)
	}

	// Import GitOps : dates RFC3339 (format de l'export), ramenées au format de CURRENT_TIMESTAMP.
	starts := time.Now().Add(-time.Minute)
	doc := "version: 1\nsilences:\n  - name: import\n    starts_at: " + starts.UTC().Format(time.RFC3339) +
		"\n    ends_at: " + starts.Add(time.Hour).UTC().Format(time.RFC3339) + "\n  - name: illisible\n    starts_at: demain\n    ends_at: après-demain\n"
	rec := serve(t, h, http.MethodPost, "/api/v1/rules-engine/import", doc)
	var summary map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil || summary["silences_created"] != 1 {
		t.Fatalf("import : %s (le silence aux dates illisibles est ignoré)", rec.Body)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM automation_silences WHERE name='import' AND starts_at=? AND starts_at <= CURRENT_TIMESTAMP`, //nolint:errcheck
		sqltime.Format(starts)).Scan(&n)
	if n != 1 {
		t.Error("le silence importé doit être stocké au format de CURRENT_TIMESTAMP et déjà commencé")
	}
}

func TestNodeTokenExpiryIgnoresTheProcessTimezone(t *testing.T) {
	withLocalZone(t, -5)
	db := openSQLDatesDB(t)
	h := &TokensHandler{DB: db, Log: slog.Default()}
	rec := serve(t, h, http.MethodPost, "/api/v1/tokens", map[string]any{"role": "edge", "node_name": "lyon-03", "ttl_hours": 1})
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : status %d %s", rec.Code, rec.Body)
	}
	var created struct{ Token string }
	json.Unmarshal(rec.Body.Bytes(), &created) //nolint:errcheck

	// Heure locale UTC-5 comparée en texte à CURRENT_TIMESTAMP (UTC) : le token naissait expiré.
	auth := adminauth.RequireBearerToken(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	authRec := httptest.NewRecorder()
	auth.ServeHTTP(authRec, req)
	if authRec.Code != http.StatusOK {
		t.Fatalf("token valide 1 h rejeté aussitôt : status %d", authRec.Code)
	}

	for id, age := range map[string]time.Duration{"old": 7*24*time.Hour + 2*time.Hour, "recent": 7*24*time.Hour - 2*time.Hour} {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, revoked, created_at) VALUES (?, ?, 'edge', 'x', 1, ?)`,
			id, id, sqltime.Format(time.Now().Add(-age))); err != nil {
			t.Fatal(err)
		}
	}
	if rec := serve(t, h, http.MethodPost, "/api/v1/tokens/purge-expired", map[string]int{"days": 7}); rec.Code != http.StatusOK {
		t.Fatalf("purge : status %d %s", rec.Code, rec.Body)
	}
	var left []string
	rows, _ := db.Query(`SELECT id FROM tokens WHERE revoked=1`)
	for rows.Next() {
		var id string
		rows.Scan(&id) //nolint:errcheck
		left = append(left, id)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "recent" {
		t.Errorf("purge à 7 jours : restent %v, attendu [recent]", left)
	}
}

func TestPATExpirySurvivesTheUsersArchive(t *testing.T) {
	db := openSQLDatesDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'a@example.com', 'x', 'user')`); err != nil {
		t.Fatal(err)
	}
	jwt, err := adminauth.SignJWT("u1", "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	body, _ := json.Marshal(map[string]any{"label": "ci", "scopes": []string{"certs:read"},
		"expires_at": exp.In(time.FixedZone("", 2*3600)).Format(time.RFC3339)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()
	adminauth.RequireJWT("secret")(&UserTokensHandler{DB: db, Log: slog.Default()}).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création du PAT : status %d %s", rec.Code, rec.Body)
	}

	// users.yaml est lu via strftime(expires_at), NULL pour un time.Time lié tel quel : l'expiration
	// était perdue, et un PAT restauré depuis le fichier n'expirait plus.
	dir := t.TempDir()
	if err := archstore.NewUserStore(dir).SyncFromDB(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	restored := openSQLDatesDB(t)
	if err := archstore.NewUserStore(dir).LoadIntoDB(context.Background(), restored); err != nil {
		t.Fatal(err)
	}
	var got sql.NullString
	restored.QueryRow(`SELECT CAST(expires_at AS TEXT) FROM user_api_tokens`).Scan(&got) //nolint:errcheck
	if got.String != sqltime.Format(exp) {
		t.Fatalf("expiration du PAT restauré depuis users.yaml : %q, attendu %q", got.String, sqltime.Format(exp))
	}
}

func TestBootstrapTicketAutoAcceptsUntilItExpires(t *testing.T) {
	db := openSQLDatesDB(t)
	(&BootstrapHandler{DB: db}).ensureTable()
	// Ancien stockage (time.Time UTC lié tel quel) et nouveau : expirent dans 1 min, le même jour UTC
	// (sauf à minuit) : la borne RFC3339 les donnait pour expirés depuis minuit.
	exp := time.Now().UTC().Add(time.Minute)
	for tok, v := range map[string]any{"legacy": exp, "sqlite": sqltime.Format(exp)} {
		if _, err := db.Exec(`INSERT INTO bootstrap_tickets (token, payload, expires_at) VALUES (?, ?, ?)`,
			tok, `{"auto_accept":true,"node_names":["`+tok+`-edge"]}`, v); err != nil {
			t.Fatal(err)
		}
		if !BootstrapTicketAutoAccept(db, tok+"-edge") {
			t.Errorf("%s : ticket valide encore 1 min, l'acceptation automatique doit s'appliquer", tok)
		}
	}
}
