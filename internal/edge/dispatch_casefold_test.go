// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestLocationProtectionIgnoresCase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := testEdgeServer()
	s.health = proxy.NewBackendHealth(s.log.Logger())
	route := &router.Route{
		ID: "casefold", Host: "casefold.test", Type: router.RouteHTTP,
		Backends: []router.Backend{{URL: backend.URL}},
		Locations: []router.Location{{
			Path: "/api/v1/admin", PathType: "prefix",
			IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"0.0.0.0/0"}},
		}},
	}
	for path, want := range map[string]int{
		"/api/v1/admin/x":   http.StatusForbidden,
		"/API/V1/ADMIN/x":   http.StatusForbidden,
		"/api/v1/%41dmin/x": http.StatusForbidden,
		"/api/v1/public":    http.StatusOK,
	} {
		req := httptest.NewRequest(http.MethodGet, "http://casefold.test"+path, nil)
		req.RemoteAddr = "203.0.113.9:1234"
		loc := router.MatchLocation(route, req.URL.Path)
		r := route
		locPath := ""
		if loc != nil {
			locPath = loc.Path
			r = router.MergeLocation(route, loc)
		}
		rr := httptest.NewRecorder()
		s.handlerForRoute(r, locPath).ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s: %d, attendu %d", path, rr.Code, want)
		}
	}
}
