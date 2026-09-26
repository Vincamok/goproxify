package api

import (
	"context"
	"path/filepath"

	"encoding/json"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func buckets(counts ...float64) []latBucket {
	bounds := []float64{0.05, 0.1, 0.5}
	out := make([]latBucket, len(counts))
	for i, c := range counts {
		out[i] = latBucket{Le: bounds[i], Count: c}
	}
	return out
}

func sampleOnce(s *ProxyMetricsSampler, edge string, st []hostCounters, at time.Time) {
	acc := map[string]*hostWindow{}
	s.ingestEdge(acc, edge, st, at)
	s.commit(acc, at)
}

func TestSamplerRateAndErrors(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: 100, Errors: 1, DurationSumS: 5, DurationCount: 100, LatencyBuckets: buckets(90, 100, 100)}}, t0)
	if len(s.series["a.lan"]) != 0 {
		t.Fatal("le premier relevé ne doit pas produire de point")
	}
	// +50 requêtes en 10 s dont 5 en 5xx ; latences toutes < 50 ms
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: 150, Errors: 6, DurationSumS: 6, DurationCount: 150, LatencyBuckets: buckets(140, 150, 150)}}, t0.Add(10*time.Second))
	ser := s.series["a.lan"]
	if len(ser) != 1 {
		t.Fatalf("1 point attendu, %d obtenus", len(ser))
	}
	if ser[0].RPS != 5 {
		t.Errorf("rps = %v, attendu 5", ser[0].RPS)
	}
	if ser[0].ErrRate != 0.1 {
		t.Errorf("error_rate = %v, attendu 0.1", ser[0].ErrRate)
	}
	if ser[0].P95ms <= 0 || ser[0].P95ms > 50 {
		t.Errorf("p95 = %v ms, attendu dans ]0,50]", ser[0].P95ms)
	}
}

func TestSamplerCounterReset(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: 1000, DurationCount: 1000, LatencyBuckets: buckets(1000, 1000, 1000)}}, t0)
	// redémarrage de la passerelle : compteurs repartent de 20
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: 20, DurationCount: 20, LatencyBuckets: buckets(20, 20, 20)}}, t0.Add(10*time.Second))
	got := s.series["a.lan"][0].RPS
	if got != 2 {
		t.Errorf("rps après remise à zéro = %v, attendu 2 (jamais négatif)", got)
	}
}

func TestSamplerSumsEdges(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	for _, e := range []string{"e1", "e2"} {
		sampleOnce(s, e, []hostCounters{{Host: "a.lan", Requests: 0}}, t0)
	}
	acc := map[string]*hostWindow{}
	t1 := t0.Add(10 * time.Second)
	s.ingestEdge(acc, "e1", []hostCounters{{Host: "a.lan", Requests: 30}}, t1)
	s.ingestEdge(acc, "e2", []hostCounters{{Host: "a.lan", Requests: 20}}, t1)
	s.commit(acc, t1)
	if got := s.series["a.lan"][0].RPS; got != 5 {
		t.Errorf("rps cumulé = %v, attendu 5", got)
	}
}

func TestSamplerCapacityAndEviction(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan"}, {Host: "old.lan"}}, t0)
	for i := 1; i <= proxyMetricsCapacity+10; i++ {
		sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: float64(i)}}, t0.Add(time.Duration(i)*10*time.Second))
	}
	if n := len(s.series["a.lan"]); n != proxyMetricsCapacity {
		t.Errorf("série = %d points, attendu %d", n, proxyMetricsCapacity)
	}
	if _, ok := s.series["old.lan"]; ok {
		t.Error("un host absent depuis plus d'une heure doit être purgé")
	}
}

func TestProxyMetricsHandler(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	sampleOnce(s, "e1", []hostCounters{{Host: "a.lan"}}, t0)
	for i := 1; i <= 5; i++ {
		sampleOnce(s, "e1", []hostCounters{{Host: "a.lan", Requests: float64(i * 10)}}, t0.Add(time.Duration(i)*10*time.Second))
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/proxies?points=3", nil))
	var body struct {
		Proxies []struct {
			Host   string    `json:"host"`
			RPS    float64   `json:"requests_per_second"`
			Series []float64 `json:"series"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Proxies) != 1 || len(body.Proxies[0].Series) != 3 || body.Proxies[0].RPS != 1 {
		t.Fatalf("réponse inattendue : %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/metrics/proxies", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST → %d, attendu 405", rec.Code)
	}
}

// Relevé de bout en bout : passerelle simulée (HTTP), token chiffré au repos, deux relevés successifs.
func TestSamplerSampleAgainstEdge(t *testing.T) {
	auth.ConfigureNodeTokenKey("test-jwt-secret")
	defer auth.ConfigureNodeTokenKey("")
	plain := "gpx_edge_plaintext_abc123"
	stored, _ := auth.PrepareNodeTokenForStore(plain)

	requests := 100.0
	var gotAuth string
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{"proxies": []hostCounters{{ //nolint:errcheck
			Host: "a.lan", Requests: requests, DurationCount: requests, DurationSumS: requests / 100,
			LatencyBuckets: []latBucket{{Le: 0.05, Count: requests}, {Le: 0.1, Count: requests}},
		}}})
	}))
	defer edge.Close()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES ('tok-1', ?, 'edge', 'edge-1', ?)`,
		stored, edge.URL); err != nil {
		t.Fatal(err)
	}

	s := NewProxyMetricsSampler(db, nil)
	s.Sample(context.Background())
	if gotAuth != "Bearer "+plain {
		t.Fatalf("Authorization = %q, attendu le token en clair", gotAuth)
	}
	time.Sleep(20 * time.Millisecond)
	requests = 300
	s.Sample(context.Background())
	ser := s.series["a.lan"]
	if len(ser) != 1 || ser[0].RPS <= 0 {
		t.Fatalf("série inattendue : %+v", ser)
	}
}

func TestOverview(t *testing.T) {
	s := NewProxyMetricsSampler(nil, nil)
	t0 := time.Unix(1000, 0)
	for _, e := range []string{"e1", "e2"} {
		sampleOnce(s, e, []hostCounters{{Host: "a.lan"}}, t0)
	}
	acc := map[string]*hostWindow{}
	t1 := t0.Add(10 * time.Second)
	s.ingestEdge(acc, "e1", []hostCounters{{Host: "a.lan", Requests: 100, Errors: 10}}, t1)
	s.ingestEdge(acc, "e2", []hostCounters{{Host: "a.lan", Requests: 100, Errors: 0}}, t1)
	s.commit(acc, t1)
	s.recordEdgeExtras("e1", edgeSummary{BytesIn: 10, BytesOut: 20, Certs: []edgeCert{{Domain: "a.lan", ExpSecs: 500}}})
	s.recordEdgeExtras("e2", edgeSummary{BytesIn: 1, BytesOut: 2, Certs: []edgeCert{{Domain: "a.lan", ExpSecs: 100}}})

	global, edges, certs := s.Overview()
	if global["requests_per_second"] != 20.0 {
		t.Errorf("rps global = %v, attendu 20", global["requests_per_second"])
	}
	if global["error_rate_5xx"] != 0.05 {
		t.Errorf("error_rate_5xx = %v, attendu 0.05", global["error_rate_5xx"])
	}
	if global["bytes_in_total"] != 11.0 || global["bytes_out_total"] != 22.0 {
		t.Errorf("octets = %v / %v, attendu 11 / 22", global["bytes_in_total"], global["bytes_out_total"])
	}
	if len(edges) != 2 || edges[0].EdgeName != "e1" || edges[0].RequestsPerSecond != 10 {
		t.Errorf("passerelles inattendues : %+v", edges)
	}
	if len(certs) != 1 || certs[0].ExpiresInSeconds != 100 {
		t.Errorf("certificats : la plus proche expiration attendue, obtenu %+v", certs)
	}

	s.pruneEdges(map[string]bool{"e1": true})
	_, edges, _ = s.Overview()
	if len(edges) != 1 || edges[0].EdgeName != "e1" {
		t.Errorf("une passerelle retirée doit être oubliée : %+v", edges)
	}
}
