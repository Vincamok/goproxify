package admin

import "testing"

func TestIsPollingRead(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
		want         bool
	}{
		{"GET", "/api/v1/nodes/live", 200, true},
		{"GET", "/api/v1/metrics/proxies", 200, true},
		{"GET", "/api/v1/prism/kpis", 200, true},
		{"GET", "/api/v1/nodes/live", 500, false},
		{"POST", "/api/v1/prism/anything", 200, false},
		{"GET", "/api/v1/proxies", 200, false},
		{"GET", "/static/app.js", 200, true},
		{"GET", "/static/app.js", 404, false},
		{"GET", "/api/v1/export.js", 200, false},
		{"GET", "/login", 200, false},
	}
	for _, c := range cases {
		if got := isPollingRead(c.method, c.path, c.status); got != c.want {
			t.Errorf("%s %s %d : %v, attendu %v", c.method, c.path, c.status, got, c.want)
		}
	}
}
