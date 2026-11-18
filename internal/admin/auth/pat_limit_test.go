// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func patLimitFixture(t *testing.T) (h http.Handler, valid string, locks *[]string) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'u@test.local', 'x', 'admin')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	valid = auth.GeneratePAT()
	if _, err := db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES ('p1','u1','t',?,?)`,
		auth.HashPAT(valid), auth.PATPreview(valid)); err != nil {
		t.Fatalf("insert pat: %v", err)
	}
	locked := []string{}
	h = auth.RequirePAT(db, auth.WithPATLockoutHook(func(_ *http.Request, ip string) {
		locked = append(locked, ip)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	return h, valid, &locked
}

func patCall(h http.Handler, remote, token, query string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/mcp"+query, nil)
	r.RemoteAddr = remote + ":4000"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// Des jetons refusés en rafale verrouillent l'adresse (429), y compris pour un jeton valide ; une autre adresse passe, et
// le verrouillage est signalé une seule fois.
func TestRequirePATLocksAddressAfterRepeatedFailures(t *testing.T) {
	h, valid, locks := patLimitFixture(t)
	bad := auth.PATPrefix + "00000000000000000000000000000000"

	for i := 0; i < 10; i++ {
		if rr := patCall(h, "198.51.100.7", bad, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("échec %d : code=%d, attendu 401", i+1, rr.Code)
		}
	}
	rr := patCall(h, "198.51.100.7", valid, "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("adresse verrouillée : code=%d, attendu 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After attendu")
	}
	if rr := patCall(h, "198.51.100.8", valid, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("autre adresse : code=%d, attendu 204", rr.Code)
	}
	patCall(h, "198.51.100.7", bad, "")
	if len(*locks) != 1 || (*locks)[0] != "198.51.100.7" {
		t.Fatalf("hook de verrouillage = %v, attendu une seule fois 198.51.100.7", *locks)
	}
}

// Un jeton absent ne compte pas (client mal réglé, sonde) ; un jeton valide non plus, et il ne remet pas le compteur à zéro.
func TestRequirePATCountsOnlyRejectedTokens(t *testing.T) {
	h, valid, _ := patLimitFixture(t)
	bad := auth.PATPrefix + "11111111111111111111111111111111"

	for i := 0; i < 30; i++ {
		patCall(h, "198.51.100.9", "", "")
		if rr := patCall(h, "198.51.100.9", valid, ""); rr.Code != http.StatusNoContent {
			t.Fatalf("jeton valide refusé au tour %d : %d", i, rr.Code)
		}
	}
	for i := 0; i < 9; i++ {
		patCall(h, "198.51.100.9", bad, "")
		patCall(h, "198.51.100.9", valid, "")
	}
	patCall(h, "198.51.100.9", bad, "")
	if rr := patCall(h, "198.51.100.9", valid, ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("les succès intercalés ne doivent pas vider le compteur : code=%d", rr.Code)
	}
}

// Le jeton n'est pas lu dans l'URL sur /mcp, avec ou sans Accept: text/event-stream (les clients SSE l'envoient).
func TestRequirePATIgnoresAuthQueryParam(t *testing.T) {
	h, valid, _ := patLimitFixture(t)
	for _, path := range []string{"/mcp", "/mcp/sse"} {
		r := httptest.NewRequest(http.MethodGet, path+"?_auth="+valid, nil)
		r.RemoteAddr = "198.51.100.10:4000"
		r.Header.Set("Accept", "text/event-stream")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s?_auth= : code=%d, attendu 401", path, rr.Code)
		}
	}
}

// La porte d'origine passe avant le jeton : un appelant écarté reçoit 403 quel que soit son jeton, et ses jetons faux ne
// comptent pas (il n'atteint ni la base ni le limiteur).
func TestRequirePATSourceGateRunsBeforeToken(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	locked := 0
	h := auth.RequirePAT(db,
		auth.WithPATSourceGate(func(r *http.Request) bool { return r.RemoteAddr == "203.0.113.5:4000" }),
		auth.WithPATLockoutHook(func(*http.Request, string) { locked++ }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	bad := auth.PATPrefix + "22222222222222222222222222222222"
	for i := 0; i < 30; i++ {
		if rr := patCall(h, "198.51.100.11", bad, ""); rr.Code != http.StatusForbidden {
			t.Fatalf("hors liste : code=%d, attendu 403", rr.Code)
		}
	}
	if locked != 0 {
		t.Fatalf("un appelant écarté ne doit pas déclencher le limiteur (%d)", locked)
	}
	if rr := patCall(h, "203.0.113.5", bad, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("listé, jeton faux : code=%d, attendu 401", rr.Code)
	}
}

// Une même option passée à deux RequirePAT (/mcp et /mcp/) partage le compteur : le budget d'échecs n'est pas doublé.
func TestRequirePATSharesLimiterAcrossRoutes(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	opt := auth.WithPATLockoutHook(func(*http.Request, string) {})
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	a, b := auth.RequirePAT(db, opt)(ok), auth.RequirePAT(db, opt)(ok)

	bad := auth.PATPrefix + "33333333333333333333333333333333"
	for i := 0; i < 5; i++ {
		patCall(a, "198.51.100.12", bad, "")
		patCall(b, "198.51.100.12", bad, "")
	}
	if rr := patCall(a, "198.51.100.12", bad, ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("5 échecs sur chaque chemin doivent verrouiller : code=%d", rr.Code)
	}
}
