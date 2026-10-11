// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestMergeRemoteBackendsDoesNotGrowAcrossSyncs(t *testing.T) {
	local := []router.Backend{{URL: "http://10.0.0.1:80", ContainerID: "c1"}}
	pool := local
	for i := 0; i < 20; i++ {
		// le pair renvoie ce qu'il possède, y compris un backend qui est déjà chez nous
		remote := []router.Backend{
			{URL: "http://10.0.0.1:80", OwnerEdgeEndpoint: "http://peer:8000"},
			{URL: "http://10.0.0.2:80", OwnerEdgeEndpoint: "http://peer:8000"},
		}
		pool = mergeRemoteBackends(pool, remote, "http://peer:8000")
	}
	if len(pool) != 2 {
		t.Fatalf("le pool a grossi à %d backends : %+v", len(pool), pool)
	}
}

func TestAgentContainerExportOmitsBackendsOwnedByOtherGateways(t *testing.T) {
	s := testEdgeServer()
	s.table.Upsert(&router.Route{
		ID: "docker-host:app.example.fr", Host: "app.example.fr",
		Backends: []router.Backend{
			{URL: "http://10.0.0.1:80", ContainerID: "c1"},
			{URL: "http://10.0.0.9:80", OwnerEdgeEndpoint: "http://peer:8000"},
		},
	})
	rr := httptest.NewRecorder()
	s.handleListAgentContainers(rr, httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "10.0.0.1") || strings.Contains(body, "10.0.0.9") {
		t.Fatalf("export = %s", body)
	}
}
