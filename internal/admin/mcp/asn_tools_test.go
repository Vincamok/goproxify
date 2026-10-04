// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/asn"
)

func TestASNTools(t *testing.T) {
	h := setupMCPDB(t)
	path := filepath.Join(t.TempDir(), "ip2asn.tsv.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("5.0.0.0\t5.0.1.255\t64500\tFR\tEXEMPLE-HEBERGEUR\n9.0.0.0\t9.0.0.255\t64501\tDE\tAUTRE\n"))
	_ = zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	h.ASN = asn.NewStore(path, "http://127.0.0.1:1/x", nil)
	var pushes, lifted int
	h.OnBansChange = func() { pushes++ }
	h.OnUnbanMany = func(ips []string) { lifted += len(ips) }
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "198.51.100.9:1"

	found, err := h.toolLookupASN(r, map[string]any{"q": "exemple"})
	if err != nil || len(found.([]api.ASNInfo)) != 1 || found.([]api.ASNInfo)[0].ASN != 64500 {
		t.Fatalf("lookup_asn : %v %v", found, err)
	}
	prev, err := h.toolPreviewASNBan(r, map[string]any{"asn": "AS64500"})
	if err != nil || prev.(map[string]any)["would_create"] != 1 {
		t.Fatalf("preview_asn_ban : %v %v", prev, err)
	}
	if n := countBans(t, h); n != 0 {
		t.Fatalf("l'aperçu a créé %d ban(s)", n)
	}
	res, err := h.toolBanASN(r, map[string]any{"asn": "64500", "reason": "scanner"})
	if err != nil || res.(api.ASNBanResult).Created != 1 || pushes != 1 || countBans(t, h) != 1 {
		t.Fatalf("ban_asn : %v %v, %d envoi(s)", res, err, pushes)
	}
	if _, err := h.toolBanASN(r, map[string]any{"asn": "64999"}); err == nil {
		t.Error("ASN inconnu accepté")
	}
	out, err := h.toolUnbanASN(r, map[string]any{"asn": "AS64500"})
	if err != nil || out.(map[string]any)["removed"] != 1 || lifted != 1 || countBans(t, h) != 0 {
		t.Fatalf("unban_asn : %v %v, %d levée(s)", out, err, lifted)
	}
}

func countBans(t *testing.T, h *Handler) int {
	t.Helper()
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM security_bans`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
