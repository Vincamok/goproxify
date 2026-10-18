// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func logLines(ips ...string) string {
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(`{"time":"2026-10-01T10:00:00Z","method":"GET","path":"/","status":200,"remote_ip":"` + ip + `","user_agent":"x"}` + "\n")
	}
	return b.String()
}

func TestEraseIPRewritesCurrentRotatedAndCompressedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	rotated := filepath.Join(dir, "access-2026-09-01T00-00-00.000.log")
	compressed := filepath.Join(dir, "access-2026-08-01T00-00-00.000.log.gz")
	unrelated := filepath.Join(dir, "other.log")

	// IPv6 écrite en notation non canonique : trouvée quelle que soit la notation de la demande.
	cur := logLines("203.0.113.42", "198.51.100.9", "2001:DB8:0:0:0:0:0:1") + "ligne non JSON\n"
	if err := os.WriteFile(path, []byte(cur), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rotated, []byte(logLines("198.51.100.9", "203.0.113.42")), 0o644); err != nil {
		t.Fatal(err)
	}
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	zw.Write([]byte(logLines("203.0.113.42", "198.51.100.9", "203.0.113.42"))) //nolint:errcheck
	zw.Close()
	if err := os.WriteFile(compressed, gzbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte(logLines("203.0.113.42")), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewAccessLogger(path)
	n, err := a.EraseIP("203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("%d lignes supprimées, attendu 4", n)
	}
	if n, err := a.EraseIP("2001:db8::1"); err != nil || n != 1 {
		t.Fatalf("IPv6 : %d lignes, err %v, attendu 1", n, err)
	}

	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read(path); strings.Contains(got, "203.0.113.42") || strings.Contains(got, "2001:DB8") || !strings.Contains(got, "198.51.100.9") || !strings.Contains(got, "ligne non JSON") {
		t.Errorf("fichier courant : %q", got)
	}
	if got := read(rotated); strings.Contains(got, "203.0.113.42") || !strings.Contains(got, "198.51.100.9") {
		t.Errorf("rotation : %q", got)
	}
	f, err := os.Open(compressed)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	f.Close()
	if got := string(raw); strings.Contains(got, "203.0.113.42") || !strings.Contains(got, "198.51.100.9") {
		t.Errorf("rotation compressée : %q", got)
	}
	if got := read(unrelated); !strings.Contains(got, "203.0.113.42") {
		t.Errorf("un fichier étranger au journal a été touché : %q", got)
	}

	// Le journal continue d'écrire dans le fichier réécrit.
	a.mu.Lock()
	a.enc.Encode(accessEntry{Method: "GET", Path: "/apres", Status: 200, RemoteIP: "192.0.2.1"}) //nolint:errcheck
	a.mu.Unlock()
	a.closer.Close()
	if got := read(path); !strings.Contains(got, "/apres") || !strings.Contains(got, "198.51.100.9") {
		t.Errorf("écriture après effacement : %q", got)
	}
}

func TestEraseIPWithoutFileIsANoop(t *testing.T) {
	a := NewAccessLogger("")
	if n, err := a.EraseIP("203.0.113.42"); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
