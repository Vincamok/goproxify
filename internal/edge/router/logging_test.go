// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"testing"
)

func TestRouteLoggingAccessLogDefault(t *testing.T) {
	cases := map[string]bool{
		`{"level":"info"}`:                  true,
		`{}`:                                true,
		`{"access_log":false}`:              false,
		`{"access_log":true,"format":"off"}`: true,
	}
	for in, want := range cases {
		var c RouteLoggingConfig
		if err := json.Unmarshal([]byte(in), &c); err != nil {
			t.Fatal(err)
		}
		if c.AccessLog != want {
			t.Errorf("%s: AccessLog=%v want %v", in, c.AccessLog, want)
		}
	}
}
