package db

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
