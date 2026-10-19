package db

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaintainTruncatesWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var mode int
	if err := d.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("auto_vacuum = %d (err %v), attendu 2 (incrémental)", mode, err)
	}

	if _, err := d.Exec(`CREATE TABLE junk (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := d.Exec(`INSERT INTO junk VALUES (?)`, strings.Repeat("x", 2000)); err != nil {
			t.Fatal(err)
		}
	}

	maintain(context.Background(), d, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	fi, err := os.Stat(path + "-wal")
	if err == nil && fi.Size() != 0 {
		t.Fatalf("WAL de %d octets après TRUNCATE, attendu 0", fi.Size())
	}
}

// Un point de contrôle qui attend des lecteurs ne doit pas bloquer les écritures plus d'un instant : avec le
// délai ordinaire de 10 s, l'agrégation et les battements des passerelles tombaient en « database is locked ».
func TestMaintainDoesNotStallWritersBehindALongReader(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`CREATE TABLE junk (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		d.Exec(`INSERT INTO junk VALUES (?)`, strings.Repeat("x", 1000))
	}

	// Lecteur long : sa vue est antérieure aux écritures suivantes, le WAL ne peut pas être recyclé.
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM junk`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		d.Exec(`INSERT INTO junk VALUES (?)`, strings.Repeat("y", 1000))
	}

	start := time.Now()
	maintain(context.Background(), d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("le point de contrôle a duré %s : les écritures auraient été bloquées d'autant", took)
	}
	if _, err := d.Exec(`INSERT INTO junk VALUES ('apres')`); err != nil {
		t.Fatalf("écriture après la maintenance : %v", err)
	}
	var timeout int
	if err := d.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 10000 {
		t.Fatalf("busy_timeout = %d (err %v) après la maintenance, attendu 10000", timeout, err)
	}
}

func TestCheckpointTimeoutEscalatesOnAHugeWAL(t *testing.T) {
	if got := checkpointTimeout(100); got != checkpointBusyTimeout {
		t.Fatalf("petit WAL : %s", got)
	}
	if got := checkpointTimeout(walForceBytes/4096 + 1); got != 10*time.Second {
		t.Fatalf("WAL de plus de 1 Go : %s, attendu 10 s", got)
	}
}
