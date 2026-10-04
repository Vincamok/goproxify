// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var tokenRe = regexp.MustCompile(`var gpxToken="([^"]+)"`)

func powHandler(cfg router.BotConfig) http.Handler {
	cfg.Enabled = true
	cfg.Mode = "challenge"
	if cfg.ChallengeSecret == "" {
		cfg.ChallengeSecret = "test-secret"
	}
	return BotProtection(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cookie", r.Header.Get("Cookie"))
		w.WriteHeader(http.StatusNoContent)
	}))
}

func browserReq(method, target string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.RemoteAddr = "203.0.113.7:4000"
	return r
}

func fetchChallenge(t *testing.T, h http.Handler) string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("GET", "/app?x=1", ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Checking your browser") {
		t.Fatalf("page de défi attendue : %d %s", rr.Code, rr.Body.String())
	}
	m := tokenRe.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatal("jeton de défi absent de la page")
	}
	return m[1]
}

// solve cherche un nonce comme le fait le navigateur.
func solve(token string, bits int) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(n)))
		if leadingZeroBits(sum[:]) >= bits {
			return strconv.Itoa(n)
		}
	}
}

func submit(h http.Handler, token, nonce string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"c": token, "n": nonce})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("POST", botChallengePath, string(body)))
	return rr
}

func TestBotChallenge_SolveThenPass(t *testing.T) {
	h := powHandler(router.BotConfig{ChallengeDifficulty: 8})
	token := fetchChallenge(t, h)

	rr := submit(h, token, solve(token, 8))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("solution valide refusée : %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != botCookie || !cookies[0].HttpOnly {
		t.Fatalf("cookie de preuve attendu (HttpOnly) : %v", cookies)
	}

	req := browserReq("GET", "/app", "")
	req.AddCookie(cookies[0])
	req.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusNoContent {
		t.Fatalf("avec preuve : %d", out.Code)
	}
	if got := out.Header().Get("X-Cookie"); got != "sid=abc" {
		t.Fatalf("le cookie de preuve ne doit pas atteindre le backend, reçu %q", got)
	}
}

func TestBotChallenge_WrongNonceRejected(t *testing.T) {
	h := powHandler(router.BotConfig{ChallengeDifficulty: 16})
	token := fetchChallenge(t, h)
	// Un nonce qui ne résout pas le défi (probabilité d'un faux positif : 2^-16 par essai).
	bad := "0"
	for n := 0; ; n++ {
		bad = strconv.Itoa(n)
		sum := sha256.Sum256([]byte(token + ":" + bad))
		if leadingZeroBits(sum[:]) < 16 {
			break
		}
	}
	if rr := submit(h, token, bad); rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("mauvais nonce accepté : %d", rr.Code)
	}
}

func TestBotChallenge_TamperedDifficultyRejected(t *testing.T) {
	h := powHandler(router.BotConfig{ChallengeDifficulty: 16})
	token := fetchChallenge(t, h)
	parts := strings.Split(token, ".")
	parts[2] = "0" // le client abaisse lui-même la difficulté
	forged := strings.Join(parts, ".")
	if rr := submit(h, forged, "1"); rr.Code != http.StatusForbidden {
		t.Fatalf("difficulté falsifiée acceptée : %d", rr.Code)
	}
}

func TestBotChallenge_BoundToClient(t *testing.T) {
	h := powHandler(router.BotConfig{ChallengeDifficulty: 8})
	token := fetchChallenge(t, h)

	// Défi résolu depuis une autre IP : refusé.
	body, _ := json.Marshal(map[string]string{"c": token, "n": solve(token, 8)})
	req := browserReq("POST", botChallengePath, string(body))
	req.RemoteAddr = "198.51.100.9:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("défi réutilisé depuis une autre IP : %d", rr.Code)
	}

	// Cookie de preuve copié sur une autre IP : défi à nouveau.
	ok := submit(h, token, solve(token, 8))
	pass := ok.Result().Cookies()[0]
	other := browserReq("GET", "/app", "")
	other.RemoteAddr = "198.51.100.9:1"
	other.AddCookie(pass)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, other)
	if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "Checking your browser") {
		t.Fatalf("cookie rejoué depuis une autre IP accepté : %d", out.Code)
	}
}

func TestBotChallenge_ForgedAndLegacyCookiesRejected(t *testing.T) {
	h := powHandler(router.BotConfig{})
	for _, v := range []string{"aaaaaaaaaaaaaaaa.deadbeef", "9999999999.deadbeef", "x"} {
		req := browserReq("GET", "/app", "")
		req.AddCookie(&http.Cookie{Name: botCookie, Value: v})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if !strings.Contains(rr.Body.String(), "Checking your browser") {
			t.Fatalf("cookie %q accepté", v)
		}
	}
}

func TestBotChallenge_ScrapingHTMLIsNotEnough(t *testing.T) {
	// Régression : l'ancien défi posait un cookie signé directement dans la page.
	h := powHandler(router.BotConfig{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("GET", "/", ""))
	if strings.Contains(rr.Body.String(), botCookie+"=") {
		t.Fatal("la page ne doit pas contenir de cookie de preuve prêt à l'emploi")
	}
}

func TestBotChallenge_NonGETGets403(t *testing.T) {
	h := powHandler(router.BotConfig{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("POST", "/api/submit", "x=1"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST sans preuve : %d", rr.Code)
	}
}

func TestBotChallenge_ExemptPaths(t *testing.T) {
	h := powHandler(router.BotConfig{ChallengeExemptPaths: []string{"/api/", "/webhook"}})
	for _, p := range []string{"/api/v1/x", "/webhook"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, browserReq("GET", p, ""))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s doit échapper au défi : %d", p, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("GET", "/page", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("/page doit être défiée : %d", rr.Code)
	}
}

func TestBotChallenge_DifficultyIsCapped(t *testing.T) {
	c := newBotChallenge(&router.BotConfig{ChallengeDifficulty: 99}, "s")
	if c.bits != maxChallengeBits {
		t.Fatalf("bits = %d", c.bits)
	}
	if c := newBotChallenge(&router.BotConfig{}, "s"); c.bits != defaultChallengeBits || c.provider != "pow" {
		t.Fatalf("défauts : bits=%d provider=%s", c.bits, c.provider)
	}
}

func TestBotChallenge_Captcha(t *testing.T) {
	var gotSecret, gotToken, gotIP string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		gotSecret, gotToken, gotIP = r.Form.Get("secret"), r.Form.Get("response"), r.Form.Get("remoteip")
		json.NewEncoder(w).Encode(map[string]bool{"success": r.Form.Get("response") == "good"}) //nolint:errcheck
	}))
	defer verifier.Close()
	old := captchaVerifyURL["turnstile"]
	captchaVerifyURL["turnstile"] = verifier.URL
	defer func() { captchaVerifyURL["turnstile"] = old }()

	h := powHandler(router.BotConfig{ChallengeProvider: "turnstile", ChallengeSiteKey: "SITE", ChallengeProviderSecret: "SECRET"})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("GET", "/", ""))
	if !strings.Contains(rr.Body.String(), `data-sitekey="SITE"`) || strings.Contains(rr.Body.String(), "SECRET") {
		t.Fatalf("widget Turnstile attendu, sans fuite du secret : %s", rr.Body.String())
	}

	post := func(token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"t": token})
		out := httptest.NewRecorder()
		h.ServeHTTP(out, browserReq("POST", botChallengePath, string(body)))
		return out
	}
	if out := post("bad"); out.Code != http.StatusForbidden {
		t.Fatalf("jeton refusé par le fournisseur accepté : %d", out.Code)
	}
	out := post("good")
	if out.Code != http.StatusNoContent || len(out.Result().Cookies()) != 1 {
		t.Fatalf("jeton valide refusé : %d", out.Code)
	}
	if gotSecret != "SECRET" || gotToken != "good" || gotIP != "203.0.113.7" {
		t.Fatalf("requête de vérification : secret=%q token=%q ip=%q", gotSecret, gotToken, gotIP)
	}
}

func TestBotChallenge_CaptchaFailsClosedWhenProviderDown(t *testing.T) {
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := verifier.URL
	verifier.Close()
	old := captchaVerifyURL["hcaptcha"]
	captchaVerifyURL["hcaptcha"] = url
	defer func() { captchaVerifyURL["hcaptcha"] = old }()

	h := powHandler(router.BotConfig{ChallengeProvider: "hcaptcha", ChallengeSiteKey: "k", ChallengeProviderSecret: "s"})
	body, _ := json.Marshal(map[string]string{"t": "anything"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, browserReq("POST", botChallengePath, string(body)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("fournisseur injoignable : %d", rr.Code)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want int
	}{
		{[]byte{0x80}, 0}, {[]byte{0x40}, 1}, {[]byte{0x00, 0x01}, 15}, {[]byte{0, 0}, 16}, {[]byte{0x0f, 0xff}, 4},
	} {
		if got := leadingZeroBits(tc.in); got != tc.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
