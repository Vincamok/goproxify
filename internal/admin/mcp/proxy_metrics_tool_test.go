// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"
)

func TestGetProxyMetricsToolRegistered(t *testing.T) {
	for _, tool := range tools {
		if tool["name"] == "get_proxy_metrics" {
			return
		}
	}
	t.Fatal("outil manquant: get_proxy_metrics")
}

func TestToolGetProxyMetrics(t *testing.T) {
	type entry struct {
		Host   string    `json:"host"`
		RPS    float64   `json:"requests_per_second"`
		Series []float64 `json:"series"`
	}
	h := &Handler{ProxyMetrics: func(points int) (any, any) {
		return []entry{{Host: "a.lan", RPS: 2, Series: []float64{1, 2}}, {Host: "b.lan", RPS: 5}}, nil
	}}

	res, err := h.toolGetProxyMetrics("a.lan", 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	var out struct {
		Proxies []entry `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Proxies) != 1 || out.Proxies[0].Host != "a.lan" {
		t.Fatalf("filtre par host inattendu : %s", raw)
	}

	if _, err := (&Handler{}).toolGetProxyMetrics("", 0); err == nil {
		t.Fatal("erreur attendue sans source de métriques")
	}
}
