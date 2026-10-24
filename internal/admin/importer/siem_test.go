// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

func siemConfigWithTokens() siem.Config {
	return siem.Config{Enabled: true, Destinations: []siem.Destination{
		{ID: "d1", Name: "Datadog", Type: siem.TypeHTTP, Address: "https://http-intake.logs.datadoghq.eu/api/v2/logs",
			Headers: map[string]string{"DD-API-KEY": "jeton-datadog-42", "X-Region": "eu"}},
		{ID: "d2", Name: "Syslog", Type: siem.TypeSyslog, Address: "siem:6514", TLS: true},
	}}
}

// Les valeurs d'en-têtes d'une destination SIEM sortent de la section standard quel que soit leur nom (on ne sait pas lequel
// porte le jeton) et reviennent par la section secrets chiffrée.
func TestSIEMTokensLeaveTheStandardSectionAndComeBackWithTheSecrets(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-siem")
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := siemcfg.Save(src, siemConfigWithTokens()); err != nil {
		t.Fatal(err)
	}
	bk := &Backup{Tables: exportTables(src)}
	RedactSecrets(bk)
	if _, err := AttachSecrets(src, bk, nil, nil); err != nil {
		t.Fatal(err)
	}
	standard, _ := json.Marshal(bk.Tables)
	if strings.Contains(string(standard), "jeton-datadog-42") {
		t.Fatal("le jeton est lisible dans la section standard")
	}
	if !strings.Contains(string(standard), "Datadog") || !strings.Contains(string(standard), "X-Region") {
		t.Fatalf("la configuration non secrète doit rester dans la section standard : %s", standard)
	}
	raw, _ := json.Marshal(bk)
	if strings.Contains(string(raw), "jeton-datadog-42") {
		t.Fatal("le jeton est lisible dans le snapshot : la section secrets n'est pas chiffrée")
	}

	// Restauration sur un Admin neuf : la configuration seule laisse l'en-tête vide, les secrets rendent le jeton.
	dst, err := admindb.Open(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if res := Apply(dst, bk, ImportSelection{ImportConfig: true, AllowPrivileged: true}); res.Config == 0 {
		t.Fatalf("restauration de la configuration : %+v", res)
	}
	got := siemcfg.Load(dst)
	if len(got.Destinations) != 2 || got.Destinations[0].Headers["DD-API-KEY"] != "" || got.Destinations[0].Headers["X-Region"] != "" {
		t.Fatalf("configuration restaurée : %+v", got.Destinations)
	}
	if res := Apply(dst, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true}); res.SecretsError != "" {
		t.Fatalf("restauration des secrets : %+v", res)
	}
	if got := siemcfg.Load(dst); got.Destinations[0].Headers["DD-API-KEY"] != "jeton-datadog-42" || !got.Enabled {
		t.Fatalf("jeton non restauré : %+v", got.Destinations[0])
	}
}

// Restaurer la section standard sur un Admin qui a déjà sa configuration n'efface pas ses jetons.
func TestRestoringTheStandardSectionKeepsTheTokensAlreadyInPlace(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-siem")
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	cfg := siemConfigWithTokens()
	if err := siemcfg.Save(src, cfg); err != nil {
		t.Fatal(err)
	}
	bk := &Backup{Tables: exportTables(src)}
	RedactSecrets(bk)

	// Le snapshot est plus ancien : une destination a été ajoutée depuis, et un jeton changé.
	cfg.Destinations[0].Headers["DD-API-KEY"] = "jeton-renouvele"
	cfg.Destinations = append(cfg.Destinations, siem.Destination{ID: "d3", Name: "Nouveau", Type: siem.TypeHTTP, Address: "http://x/", Headers: map[string]string{"Authorization": "Bearer neuf"}})
	if err := siemcfg.Save(src, cfg); err != nil {
		t.Fatal(err)
	}
	if res := Apply(src, bk, ImportSelection{ImportConfig: true, AllowPrivileged: true, OnConflict: "overwrite"}); res.Config == 0 {
		t.Fatalf("restauration : %+v", res)
	}
	got := siemcfg.Load(src)
	for _, d := range got.Destinations {
		if d.ID == "d1" && d.Headers["DD-API-KEY"] != "jeton-renouvele" {
			t.Errorf("le jeton en place a été effacé : %q", d.Headers["DD-API-KEY"])
		}
	}
}

// La file des effacements d'IP à rejouer est une obligation : elle part avec les secrets (ses IP sont chiffrées par la
// clé RGPD, qui y est aussi), jamais perdue à la restauration.
func TestErasureQueueTravelsWithTheSecrets(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-file")
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	src.Exec(`INSERT INTO edge_erasure_queue (ip_enc) VALUES ('chiffre-1'), ('chiffre-2')`)
	bk := &Backup{Tables: exportTables(src)}
	RedactSecrets(bk)
	if _, err := AttachSecrets(src, bk, nil, nil); err != nil {
		t.Fatal(err)
	}
	standard, _ := json.Marshal(bk.Tables)
	if strings.Contains(string(standard), "chiffre-1") {
		t.Fatal("la file d'effacement est dans la section standard")
	}
	dst, err := admindb.Open(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if res := Apply(dst, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true}); res.SecretsError != "" {
		t.Fatalf("restauration : %+v", res)
	}
	var n int
	dst.QueryRow(`SELECT COUNT(*) FROM edge_erasure_queue`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d ordres d'effacement restaurés, attendu 2", n)
	}
}

// Les positions des flux de lignes suivent les lignes dans l'historique ; celles des cumuls et des compteurs n'y sont pas :
// ces données se reconstituent depuis les passerelles.
func TestHistoryCarriesTheLineStreamCursorsOnly(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-curseurs")
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, c := range [][3]any{{"n1", "access", int64(1)<<40 | 30}, {"n1", "system", int64(3)<<20 | 7}, {"n1", "minute", int64(99999)}, {"n1", "iperr", int64(5)}} {
		src.Exec(`INSERT INTO edge_log_cursors (node_id, stream, last_seq) VALUES (?, ?, ?)`, c[0], c[1], c[2])
	}
	src.Exec(`INSERT INTO logs (ts, ip, path, message) VALUES ('2026-10-01 10:00:00','203.0.113.9','/login','ligne')`)
	bk := &Backup{}
	if err := AttachHistory(src, bk); err != nil {
		t.Fatal(err)
	}
	sum, err := OpenHistorySummary(bk)
	if err != nil || sum.Tables["edge_log_cursors"] != 2 || sum.Truncated["edge_log_cursors"] != 0 {
		t.Fatalf("résumé : %+v, %v", sum, err)
	}
	dst, err := admindb.Open(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if res := Apply(dst, bk, ImportSelection{ImportHistory: true, AllowPrivileged: true}); res.HistoryError != "" {
		t.Fatalf("restauration : %+v", res)
	}
	rows, err := dst.Query(`SELECT stream, last_seq FROM edge_log_cursors WHERE node_id = 'n1' ORDER BY stream`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int64{}
	for rows.Next() {
		var s string
		var n int64
		rows.Scan(&s, &n)
		got[s] = n
	}
	if len(got) != 2 || got["access"] != int64(1)<<40|30 || got["system"] != int64(3)<<20|7 {
		t.Fatalf("positions restaurées : %v", got)
	}
}
