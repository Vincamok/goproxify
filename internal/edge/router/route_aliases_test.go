// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRouteUnmarshalAliases(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []string
	}{
		"liste":     {`{"host":"a.fr","aliases":["b.fr","c.fr"]}`, []string{"b.fr", "c.fr"}},
		"chaine":    {`{"host":"a.fr","aliases":"b.fr"}`, []string{"b.fr"}},
		"virgules":  {`{"host":"a.fr","aliases":"b.fr, c.fr"}`, []string{"b.fr", "c.fr"}},
		"pointvirg": {`{"host":"a.fr","aliases":"b.fr;c.fr"}`, []string{"b.fr", "c.fr"}},
		"absent":    {`{"host":"a.fr"}`, nil},
		"null":      {`{"host":"a.fr","aliases":null}`, nil},
	}
	for name, c := range cases {
		var r Route
		if err := json.Unmarshal([]byte(c.in), &r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Host != "a.fr" || !reflect.DeepEqual(r.Aliases, c.want) {
			t.Errorf("%s: host=%q aliases=%v, attendu %v", name, r.Host, r.Aliases, c.want)
		}
	}
	var r Route
	if err := json.Unmarshal([]byte(`{"aliases":42}`), &r); err == nil {
		t.Error("aliases numérique devrait échouer")
	}
}
