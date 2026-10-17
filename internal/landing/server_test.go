package landing

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	s := New(&config.LandingConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h, err := s.handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestDefaultPageIsModern(t *testing.T) {
	rec := get(t, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="route-grid"`) {
		t.Fatalf("/ : code %d, présentation moderne attendue", rec.Code)
	}
}

func TestClassicPageStaysAvailable(t *testing.T) {
	rec := get(t, "/classic")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `id="hero"`) {
		t.Fatalf("/classic : code %d, présentation classique attendue", rec.Code)
	}
	if strings.Contains(body, `class="route-grid"`) {
		t.Fatal("/classic sert la présentation moderne")
	}
}

func TestEditorialRedirectsToDefault(t *testing.T) {
	rec := get(t, "/editorial")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/" {
		t.Fatalf("/editorial : code %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
}
