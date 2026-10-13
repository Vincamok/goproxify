package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Tant qu'un débit partagé est actif, la passerelle interroge ses pairs toutes les ~500 ms avec leur jeton ; un pair
// plus ancien (404) ou muet ne gêne ni l'autre ni la limite locale.
func TestQuotaSyncLoop_PollsPeersForSharedRates(t *testing.T) {
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/ratelimit/rates" || r.Header.Get("Authorization") != "Bearer jeton-pair" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		_, _ = w.Write([]byte(`[{"key":"sync.test\u0000203.0.113.70","rate":40}]`))
	}))
	defer peer.Close()
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()

	s := &Server{peers: proxy.NewPeerRegistry()}
	s.peers.Replace([]proxy.PeerInfo{
		{Name: "pair", Endpoint: peer.URL, Token: "jeton-pair"},
		{Name: "ancien", Endpoint: old.URL, Token: "x"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Une requête partagée admise : le débit est actif.
	h := middleware.RateLimit(&router.RateLimitConfig{RequestsPerSecond: 100, Burst: 100, Shared: true})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "http://sync.test/", nil)
	req.RemoteAddr = "203.0.113.70:1"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !middleware.HasSharedRates() {
		t.Fatal("un débit partagé admis doit activer la synchronisation")
	}

	s.startQuotaSyncLoop(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := hits.Load(); n < 3 {
		t.Fatalf("le pair n'a été interrogé que %d fois en 3 s (une demi-seconde attendue)", n)
	}
}
