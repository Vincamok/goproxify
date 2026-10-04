package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func counterVal(c prometheus.Counter) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}

func shadowDiffCount(host, kind string) float64 {
	return counterVal(metrics.Routing.ShadowDiff.WithLabelValues(host, kind))
}

func runShadowCompare(t *testing.T, host string, cfg router.ShadowConfig, primary, mirror http.HandlerFunc) {
	t.Helper()
	pb := httptest.NewServer(primary)
	sb := httptest.NewServer(mirror)
	t.Cleanup(pb.Close)
	t.Cleanup(sb.Close)
	cfg.Backend = sb.URL
	cfg.Compare = true
	route := &router.Route{ID: host, Host: host, Type: router.RouteHTTP, Backends: []router.Backend{{URL: pb.URL}}, Shadow: &cfg}
	h := NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
	before := counterVal(metrics.Routing.ShadowCompared.WithLabelValues(host))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil))
	deadline := time.Now().Add(3 * time.Second)
	for counterVal(metrics.Routing.ShadowCompared.WithLabelValues(host)) == before {
		if time.Now().After(deadline) {
			t.Fatal("comparaison shadow non effectuée")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func reply(code int, body string, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(code)
		w.Write([]byte(body))
	}
}

func TestShadowCompareDetectsDiffs(t *testing.T) {
	runShadowCompare(t, "diff.example.fr", router.ShadowConfig{CompareBody: true, CompareHeaders: []string{"X-Version"}},
		reply(200, "v1", "X-Version", "1"), reply(500, "v22", "X-Version", "2"))
	for _, k := range []string{"status", "header", "body"} {
		if shadowDiffCount("diff.example.fr", k) != 1 {
			t.Errorf("diff %s non comptée", k)
		}
	}
}

func TestShadowCompareIdenticalAndOptIn(t *testing.T) {
	runShadowCompare(t, "same.example.fr", router.ShadowConfig{CompareBody: true},
		reply(200, "same"), reply(200, "same"))
	for _, k := range []string{"status", "header", "body"} {
		if shadowDiffCount("same.example.fr", k) != 0 {
			t.Errorf("fausse différence %s", k)
		}
	}
	// corps différents mais compare_body désactivé : seul le statut compte
	runShadowCompare(t, "status.example.fr", router.ShadowConfig{}, reply(200, "a"), reply(200, "bb"))
	if shadowDiffCount("status.example.fr", "body") != 0 {
		t.Error("corps comparé sans compare_body")
	}
}
