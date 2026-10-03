// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeDocker sert /containers/json avec la liste courante de conteneurs.
func fakeDocker(containers *[]map[string]any) *Client {
	return &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(*containers)
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    r,
		}, nil
	})}}
}

type gatewayRecorder struct {
	mu    sync.Mutex
	posts []string
	stops []string
}

func newGatewayRecorder() (*gatewayRecorder, *httptest.Server) {
	rec := &gatewayRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		rec.mu.Lock()
		defer rec.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			rec.posts = append(rec.posts, p["host"].(string))
		case http.MethodDelete:
			rec.stops = append(rec.stops, p["container_id"].(string))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return rec, srv
}

func webContainer(id, host string) map[string]any {
	return map[string]any{
		"Id":    id,
		"Names": []string{"/" + host},
		"Image": "web",
		"Labels": map[string]string{
			LabelEnable: "true",
			LabelHost:   host,
		},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"net": map[string]string{"IPAddress": "172.18.0.2"}}},
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Un conteneur arrêté pendant une coupure de la passerelle est signalé arrêté à la reprise, et ceux
// qui tournent sont republiés.
func TestScanAllReannouncesAndReportsMissedStops(t *testing.T) {
	rec, srv := newGatewayRecorder()
	defer srv.Close()

	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr"), webContainer("bbbb2222bbbb2222", "b.example.fr")}
	d := NewDiscovery(fakeDocker(&containers), srv.URL, "tok", "goproxify.", "agent-1", nil, quietLogger())

	d.ScanAll(context.Background())
	if len(rec.posts) != 2 {
		t.Fatalf("scan initial : %v", rec.posts)
	}

	// a.example.fr s'arrête pendant que la passerelle est injoignable, puis la passerelle revient.
	containers = containers[1:]
	rec.posts, rec.stops = nil, nil
	d.ScanAll(context.Background())

	if len(rec.stops) != 1 || rec.stops[0] != "aaaa1111aaaa1111" {
		t.Fatalf("arrêt manqué non signalé : %v", rec.stops)
	}
	if len(rec.posts) != 1 || rec.posts[0] != "b.example.fr" {
		t.Fatalf("réannonce du conteneur restant : %v", rec.posts)
	}
	if d.IsKnown("aaaa1111aaaa1111") {
		t.Fatal("le conteneur disparu est resté dans le catalogue")
	}
}

// Un envoi qui échoue (passerelle injoignable) lève le drapeau de réannonce.
func TestFailedReportMarksDirty(t *testing.T) {
	_, srv := newGatewayRecorder()
	url := srv.URL
	srv.Close() // passerelle injoignable

	containers := []map[string]any{webContainer("aaaa1111aaaa1111", "a.example.fr")}
	d := NewDiscovery(fakeDocker(&containers), url, "tok", "goproxify.", "agent-1", nil, quietLogger())
	d.ScanAll(context.Background())
	if !d.dirty.Load() {
		t.Fatal("un envoi en échec doit déclencher une réannonce")
	}

	// La passerelle revient : la boucle de reprise consomme le drapeau.
	if !d.dirty.Swap(false) {
		t.Fatal("drapeau déjà consommé")
	}
}
