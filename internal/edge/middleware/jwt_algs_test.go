// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwksServer(t *testing.T, keys ...map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signedToken(t *testing.T, alg, kid string, sign func(msg []byte) []byte) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(map[string]any{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	signing := b64u(hdr) + "." + b64u(pl)
	return signing + "." + b64u(sign([]byte(signing)))
}

func TestValidateJWT_ECDSA(t *testing.T) {
	cases := []struct {
		alg   string
		curve elliptic.Curve
		crv   string
		size  int
		hash  func([]byte) []byte
	}{
		{"ES256", elliptic.P256(), "P-256", 32, func(m []byte) []byte { h := sha256.Sum256(m); return h[:] }},
		{"ES384", elliptic.P384(), "P-384", 48, func(m []byte) []byte { h := sha512.Sum384(m); return h[:] }},
		{"ES512", elliptic.P521(), "P-521", 66, func(m []byte) []byte { h := sha512.Sum512(m); return h[:] }},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
			srv := jwksServer(t, map[string]string{
				"kty": "EC", "kid": "k", "crv": c.crv,
				"x": b64u(key.X.FillBytes(make([]byte, c.size))), "y": b64u(key.Y.FillBytes(make([]byte, c.size))),
			})
			cache := &jwksCache{url: srv.URL, client: srv.Client()}
			sign := func(m []byte) []byte {
				r, s, _ := ecdsa.Sign(rand.Reader, key, c.hash(m))
				return append(r.FillBytes(make([]byte, c.size)), s.FillBytes(make([]byte, c.size))...)
			}
			tok := signedToken(t, c.alg, "k", sign)
			if _, err := validateJWT(tok, cache, "", ""); err != nil {
				t.Fatalf("jeton %s valide refusé: %v", c.alg, err)
			}
			bad := signedToken(t, c.alg, "k", func(m []byte) []byte { return make([]byte, 2*c.size) })
			if _, err := validateJWT(bad, cache, "", ""); err == nil {
				t.Fatalf("signature %s nulle acceptée", c.alg)
			}
		})
	}
}

func TestValidateJWT_ECDSAAlgCurveMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, map[string]string{
		"kty": "EC", "kid": "k", "crv": "P-256",
		"x": b64u(key.X.FillBytes(make([]byte, 32))), "y": b64u(key.Y.FillBytes(make([]byte, 32))),
	})
	cache := &jwksCache{url: srv.URL, client: srv.Client()}
	tok := signedToken(t, "ES512", "k", func(m []byte) []byte {
		h := sha512.Sum512(m)
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		return append(r.FillBytes(make([]byte, 66)), s.FillBytes(make([]byte, 66))...)
	})
	if _, err := validateJWT(tok, cache, "", ""); err == nil {
		t.Fatal("ES512 avec une clé P-256 doit être refusé")
	}
}

func TestValidateJWT_EdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := jwksServer(t, map[string]string{"kty": "OKP", "kid": "k", "crv": "Ed25519", "x": b64u(pub)})
	cache := &jwksCache{url: srv.URL, client: srv.Client()}
	tok := signedToken(t, "EdDSA", "k", func(m []byte) []byte { return ed25519.Sign(priv, m) })
	if _, err := validateJWT(tok, cache, "", ""); err != nil {
		t.Fatalf("EdDSA valide refusé: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad := signedToken(t, "EdDSA", "k", func(m []byte) []byte { return ed25519.Sign(other, m) })
	if _, err := validateJWT(bad, cache, "", ""); err == nil {
		t.Fatal("EdDSA signé par une autre clé accepté")
	}
}

// Un jeton RS256 ne doit pas être vérifié avec une clé EC du JWKS (et inversement).
func TestValidateJWT_KeyTypeMustMatchAlg(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t,
		map[string]string{"kty": "EC", "kid": "ec", "crv": "P-256", "x": b64u(ec.X.FillBytes(make([]byte, 32))), "y": b64u(ec.Y.FillBytes(make([]byte, 32)))},
		map[string]string{"kty": "RSA", "kid": "rsa", "n": b64u(rsaKey.N.Bytes()), "e": b64u(big.NewInt(int64(rsaKey.E)).Bytes())},
	)
	cache := &jwksCache{url: srv.URL, client: srv.Client()}
	rs := signedToken(t, "RS256", "ec", func(m []byte) []byte {
		h := sha256.Sum256(m)
		s, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
		return s
	})
	if _, err := validateJWT(rs, cache, "", ""); err == nil {
		t.Fatal("RS256 avec kid pointant une clé EC accepté")
	}
	es := signedToken(t, "ES256", "rsa", func(m []byte) []byte { return make([]byte, 64) })
	if _, err := validateJWT(es, cache, "", ""); err == nil {
		t.Fatal("ES256 avec kid pointant une clé RSA accepté")
	}
}

func TestExtractBearerToken(t *testing.T) {
	cases := []struct{ header, value, name, want string }{
		{"", "Bearer abc", "", "abc"},
		{"", "bearer abc", "", "abc"},
		{"", "Basic abc", "", ""},
		{"Authorization", "Bearer abc", "", "abc"},
		{"Authorization", "BEARER abc", "", "abc"},
		{"Authorization", "abc", "", ""},
		{"X-Token", "abc", "", "abc"},
		{"X-Token", "Bearer abc", "", "abc"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		hn := c.header
		if hn == "" {
			hn = "Authorization"
		}
		r.Header.Set(hn, c.value)
		if got := extractBearerToken(r, c.header); got != c.want {
			t.Errorf("header=%q valeur=%q: %q, attendu %q", c.header, c.value, got, c.want)
		}
	}
}

func TestJWTValidation_HeaderNameAuthorization(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, map[string]string{"kty": "RSA", "kid": "k", "n": b64u(key.N.Bytes()), "e": b64u(big.NewInt(int64(key.E)).Bytes())})
	tok := signedToken(t, "RS256", "k", func(m []byte) []byte {
		h := sha256.Sum256(m)
		s, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		return s
	})
	h := JWTValidation(&router.JWTConfig{Enabled: true, JWKSURL: srv.URL, HeaderName: "Authorization"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d, attendu 200", rec.Code)
	}
}
