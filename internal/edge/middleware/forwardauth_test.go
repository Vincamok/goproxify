package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func forwardAuthFixture(t *testing.T, authStatus int, authHeaders map[string]string, cfg router.SSOConfig) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Uri") != "/page?x=1" {
			t.Errorf("X-Forwarded-Uri = %q", r.Header.Get("X-Forwarded-Uri"))
		}
		for k, v := range authHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(authStatus)
		if authStatus >= 300 {
			_, _ = w.Write([]byte("denied"))
		}
	}))
	t.Cleanup(auth.Close)
	cfg.Enabled, cfg.Provider, cfg.ForwardAuthURL = true, "forward", auth.URL

	var seen *http.Request
	h := SSOAuth(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r }))
	req := httptest.NewRequest(http.MethodGet, "http://app.test/page?x=1", nil)
	req.RequestURI = "/page?x=1"
	req.Header.Set("X-Remote-User", "admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, seen
}

func TestForwardAuthAccepts202AndDropsForgedIdentity(t *testing.T) {
	rec, seen := forwardAuthFixture(t, http.StatusAccepted, nil, router.SSOConfig{})
	if seen == nil {
		t.Fatalf("requête non transmise au backend (code %d)", rec.Code)
	}
	if got := seen.Header.Get("X-Remote-User"); got != "" {
		t.Fatalf("X-Remote-User forgé par le client transmis au backend : %q", got)
	}
}

func TestForwardAuthCopiesWildcardHeaders(t *testing.T) {
	_, seen := forwardAuthFixture(t, http.StatusOK,
		map[string]string{"X-Authentik-Username": "alice", "X-Other": "no"},
		router.SSOConfig{HeadersToForward: []string{"X-authentik-*"}})
	if seen == nil || seen.Header.Get("X-Authentik-Username") != "alice" {
		t.Fatalf("en-tête joker non copié : %v", seen)
	}
	if seen.Header.Get("X-Other") != "" {
		t.Fatal("en-tête non listé copié")
	}
}

func TestForwardAuthRelaysDenialBody(t *testing.T) {
	rec, seen := forwardAuthFixture(t, http.StatusForbidden, nil, router.SSOConfig{})
	if seen != nil || rec.Code != http.StatusForbidden || rec.Body.String() != "denied" {
		t.Fatalf("refus mal relayé : code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestForwardAuthSignInRedirect(t *testing.T) {
	rec, _ := forwardAuthFixture(t, http.StatusUnauthorized, nil,
		router.SSOConfig{ForwardAuthSignInURL: "https://auth.test/oauth2/start"})
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || loc != "https://auth.test/oauth2/start?rd=http%3A%2F%2Fapp.test%2Fpage%3Fx%3D1" {
		t.Fatalf("code=%d location=%q", rec.Code, loc)
	}
}
