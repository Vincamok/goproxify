package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/vincamok/goproxify/internal/edge/metrics"
)

func durationSamples(t *testing.T, host string) uint64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.Edge.RequestDuration.WithLabelValues(host).(prometheus.Histogram).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestRecordRequestMetricsSkipsWebSocketDuration(t *testing.T) {
	const host = "ws-duration.test"
	plain := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	ws := httptest.NewRequest(http.MethodGet, "http://"+host+"/socket", nil)
	ws.Header.Set("Upgrade", "WebSocket")

	metrics.Edge.ActiveRequests.WithLabelValues(host).Add(2)
	recordRequestMetrics(host, plain, &statusCapture{status: http.StatusOK}, 20*time.Millisecond)
	recordRequestMetrics(host, ws, &statusCapture{status: http.StatusSwitchingProtocols}, time.Minute)

	if n := durationSamples(t, host); n != 1 {
		t.Errorf("histogramme de latence = %d échantillons, attendu 1 (le WebSocket n'en fait pas partie)", n)
	}
	if got := testutil.ToFloat64(metrics.Edge.RequestsTotal.WithLabelValues(host, http.MethodGet, "101")); got != 1 {
		t.Errorf("le WebSocket doit rester compté dans requests_total, obtenu %v", got)
	}
}
