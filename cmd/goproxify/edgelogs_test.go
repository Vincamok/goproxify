// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// La commande locale lit la base d'une passerelle sans l'Admin, avec la clé IP scellée par le secret d'appairage :
// elle exporte l'IP réelle, signe, journalise, et le gel légal qu'elle pose bloque la purge du processus de la passerelle.
func TestEdgeLogsExportAndHoldWorkWithoutTheAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_PAIRING_SECRET", "secret-d-appairage-de-test")
	t.Setenv("GPX_CONTROL_PLANE_AUTH_TOKEN", "")
	t.Setenv("GPX_EDGE_CACHE_PATH", filepath.Join(dir, "edge-cache.gpx"))
	t.Setenv("GPX_LOG_IP_KEY_PATH", filepath.Join(dir, "log-ip-key.gpx"))
	t.Setenv("GPX_LOG_SIGN_KEY_PATH", filepath.Join(dir, "log-sign-key.gpx"))
	t.Setenv("GPX_LOG_EXPORT_AUDIT_PATH", filepath.Join(dir, "audit.jsonl"))
	t.Setenv("GPX_EXPORT_PASSWORD", "")

	logsDir := filepath.Join(dir, "logs")
	cfgPath := filepath.Join(dir, "edge.json")
	cfg, _ := json.Marshal(map[string]any{"identity": map[string]any{"node_name": "gw-paris"}, "engine": map[string]any{"log_store_dir": logsDir}})
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	// La passerelle a écrit des lignes pseudonymisées avec sa clé, scellée comme elle le fait.
	key, _ := ipcrypt.NewKey()
	cache := edgecache.New(filepath.Join(dir, "edge-cache.gpx"), edgecache.ResolveSecret(""))
	if err := cache.SaveFile(filepath.Join(dir, "log-ip-key.gpx"), map[string]any{"key": key}); err != nil {
		t.Fatal(err)
	}
	st, err := logstore.Open(logstore.Options{Dir: logsDir, IPKey: key})
	if err != nil {
		t.Fatal(err)
	}
	const real = "203.0.113.42"
	at := func(s string) time.Time { ts, _ := time.Parse(time.RFC3339, s); return ts }
	e := logstore.Entry{Ts: at("2026-10-20T10:00:00Z"), Level: "info", Component: "edge", Domain: "a.example", Method: "GET", Path: "/secret", Status: 200,
		IP: "203.0.113.0", RealIP: real, IPTruncated: true}
	st.Add(logstore.KindAccess, e)
	e.Ts, e.Path, e.IP, e.RealIP, e.IPTruncated = at("2026-10-21T10:00:00Z"), "/autre", "198.51.100.5", "", false
	st.Add(logstore.KindAccess, e)
	st.Flush()
	_ = st.Close() // la passerelle est arrêtée : la commande ne doit rien lui demander

	saved := os.Args
	defer func() { os.Args = saved }()
	run := func(args ...string) {
		os.Args = append([]string{"goproxify", "edge", "logs"}, append(args, "-config", cfgPath)...)
		runEdge()
	}

	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("mot-de-passe-de-l-export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "export-2026")
	run("export", "-reason", "réquisition 2026/1234", "-from", "2026-10-20", "-to", "2026-10-31", "-ip", real, "-output", base, "-password-file", pwFile)
	run("hold", "add", "-reason", "procédure en cours", "-from", "2026-10-01", "-to", "2026-10-31")

	// Vérification par un tiers, avec la clé publique relevée à la remise.
	cacheNow := edgecache.New(filepath.Join(dir, "edge-cache.gpx"), edgecache.ResolveSecret(""))
	priv, err := logexport.LoadOrCreateKey(cacheNow, filepath.Join(dir, "log-sign-key.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	rep, err := logexport.Verify(base+".manifest.json", base+".ndjson.gpxe", "mot-de-passe-de-l-export", priv.Public().(ed25519.PublicKey), &plain)
	if err != nil || !rep.PlainChecked || rep.Manifest.Rows != 1 || rep.Manifest.Node != "gw-paris" || rep.Manifest.Reason != "réquisition 2026/1234" {
		t.Fatalf("Verify = %+v, %v", rep, err)
	}
	if !strings.Contains(plain.String(), `"ip":"`+real+`"`) || strings.Contains(plain.String(), "/autre") {
		t.Errorf("contenu exporté : %s", plain.String())
	}
	run("verify", "-manifest", base+".manifest.json", "-data", base+".ndjson.gpxe", "-password-file", pwFile,
		"-pubkey", base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), "-decrypt-to", filepath.Join(dir, "clair.ndjson"))
	if raw, _ := os.ReadFile(filepath.Join(dir, "clair.ndjson")); !bytes.Equal(raw, plain.Bytes()) {
		t.Error("le contenu déchiffré par « verify » diffère")
	}

	// Le gel est dans le registre que la passerelle relit à chaque purge.
	ro, err := logstore.Open(logstore.Options{Dir: logsDir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if holds, err := ro.Holds(); err != nil || len(holds) != 1 || holds[0].Reason != "procédure en cours" || holds[0].By == "" {
		t.Fatalf("gels = %+v, %v", holds, err)
	}
	run("hold", "list")
	run("key")

	// L'audit local garde l'export et le gel, sans l'IP, et sa chaîne est intacte.
	entries, err := logexport.Audit{Path: filepath.Join(dir, "audit.jsonl")}.Read()
	if err != nil || len(entries) != 2 || entries[0].Op != "export" || entries[1].Op != "hold_add" {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if bytes.Contains(raw, []byte(real)) {
		t.Error("l'IP filtrée est écrite dans le journal d'audit")
	}
	run("hold", "release", "-id", func() string { h, _ := ro.Holds(); return h[0].ID }())
	run("audit")
}

// Un gel par IP garde ses lignes dans une archive que l'export relit, journalise l'empreinte de l'IP (jamais l'IP), et
// lever le gel supprime l'archive.
func TestEdgeLogsHoldByIPKeepsTheRowsForTheExport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_PAIRING_SECRET", "secret-d-appairage-de-test")
	t.Setenv("GPX_CONTROL_PLANE_AUTH_TOKEN", "")
	t.Setenv("GPX_EDGE_CACHE_PATH", filepath.Join(dir, "edge-cache.gpx"))
	t.Setenv("GPX_LOG_IP_KEY_PATH", filepath.Join(dir, "log-ip-key.gpx"))
	t.Setenv("GPX_LOG_SIGN_KEY_PATH", filepath.Join(dir, "log-sign-key.gpx"))
	t.Setenv("GPX_LOG_EXPORT_AUDIT_PATH", filepath.Join(dir, "audit.jsonl"))
	logsDir := filepath.Join(dir, "logs")
	cfgPath := filepath.Join(dir, "edge.json")
	cfg, _ := json.Marshal(map[string]any{"identity": map[string]any{"node_name": "gw-paris"}, "engine": map[string]any{"log_store_dir": logsDir}})
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := logstore.Open(logstore.Options{Dir: logsDir})
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { ts, _ := time.Parse(time.RFC3339, s); return ts }
	const target = "203.0.113.42"
	for i, ip := range []string{target, "198.51.100.5"} {
		st.Add(logstore.KindAccess, logstore.Entry{Ts: at("2026-10-20T10:00:00Z").Add(time.Duration(i) * time.Minute), Level: "info", Component: "edge", Domain: "a.example",
			Method: "GET", Path: "/p", Status: 200, IP: ip})
	}
	st.Flush()
	_ = st.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	run := func(args ...string) {
		os.Args = append([]string{"goproxify", "edge", "logs"}, append(args, "-config", cfgPath)...)
		runEdge()
	}
	run("hold", "add", "-reason", "procédure ciblée", "-from", "2026-10-01", "-to", "2026-10-31", "-ip", target)
	run("hold", "list")

	ro, err := logstore.Open(logstore.Options{Dir: logsDir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	holds, err := ro.Holds()
	if err != nil || len(holds) != 1 || holds[0].IP != target {
		t.Fatalf("gels = %+v, %v", holds, err)
	}
	archive := filepath.Join(logsDir, "held", holds[0].ID)
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("archive absente : %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if bytes.Contains(raw, []byte(target)) || !bytes.Contains(raw, []byte("ip_sha256")) {
		t.Errorf("audit : %s", raw)
	}
	run("hold", "release", "-id", holds[0].ID)
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Error("l'archive du gel levé subsiste")
	}
}
