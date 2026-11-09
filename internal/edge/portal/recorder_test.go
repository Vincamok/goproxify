// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordingRoundTripEncryptedAtRest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	st, err := NewRecordingStore(dir, "secret")
	if err != nil {
		t.Fatal(err)
	}
	rec := st.Start("alice", "srv-db", "ssh", "1.2.3.4:5")
	rec.Output([]byte("hello \x1b[31mworld\x1b[0m\r\n"))
	rec.Output([]byte("é et \"guillemets\"\n"))
	id := rec.meta.ID
	rec.Close()

	list, err := st.List()
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].Actor != "alice" || list[0].Bytes == 0 {
		t.Fatalf("list: %+v %v", list, err)
	}
	cast, err := st.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(cast)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"version":2`) || !strings.Contains(lines[1], `"o"`) || !strings.Contains(lines[2], "guillemets") {
		t.Fatalf("cast inattendu: %q", cast)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, id+".cast.gpx"))
	if bytes.Contains(onDisk, []byte("hello")) {
		t.Fatal("le fichier doit être chiffré au repos")
	}
	other, _ := NewRecordingStore(dir, "autre-secret")
	if _, err := other.Read(id); err == nil {
		t.Fatal("un autre secret ne doit pas déchiffrer")
	}

	if err := st.Delete(id); err != nil {
		t.Fatal(err)
	}
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("suppression: %+v", l)
	}
}

func TestRecordingRejectsBadIDs(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	for _, id := range []string{"", "../etc/passwd", "abc", "00000000-0000-0000-0000-00000000000/../x"} {
		if _, err := st.Read(id); err == nil {
			t.Errorf("Read(%q) doit échouer", id)
		}
		if err := st.Delete(id); err == nil {
			t.Errorf("Delete(%q) doit échouer", id)
		}
	}
}

func TestRecordingTruncatesAndPurges(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	rec := st.Start("bob", "t", "web", "")
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 12; i++ {
		rec.Output(chunk)
	}
	rec.Close()
	list, _ := st.List()
	if len(list) != 1 || !list[0].Truncated || list[0].Bytes > maxRecordingBytes+(2<<20) {
		t.Fatalf("troncature attendue: %+v", list)
	}

	old := st.Start("carol", "t", "ssh", "")
	old.meta.Started = time.Now().UTC().AddDate(0, 0, -40).Format(time.RFC3339)
	old.Close()
	if n := st.Purge(30, time.Now()); n != 1 {
		t.Fatalf("purge: %d", n)
	}
	if l, _ := st.List(); len(l) != 1 || l[0].Actor != "bob" {
		t.Fatalf("après purge: %+v", l)
	}
	var nilRec *Recording
	nilRec.Output([]byte("x"))
	nilRec.Close()
	if (*RecordingStore)(nil).Start("a", "b", "c", "d") != nil {
		t.Fatal("store nul: pas d'enregistrement")
	}
}

func castKinds(t *testing.T, st *RecordingStore, id string) (kinds []string, inputs string) {
	t.Helper()
	cast, err := st.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(strings.TrimSpace(string(cast)), "\n")[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("ligne illisible %q: %v", ln, err)
		}
		kinds = append(kinds, ev[1].(string))
		if ev[1] == "i" {
			inputs += ev[2].(string)
		}
	}
	return kinds, inputs
}

func TestRecordingKeepsNoInputUnlessAsked(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	rec := st.Start("alice", "srv", "web", "")
	rec.Output([]byte("$ "))
	rec.Input([]byte("ls -la\r"))
	rec.Close()
	list, _ := st.List()
	kinds, _ := castKinds(t, st, list[0].ID)
	if list[0].Input || len(kinds) != 1 || kinds[0] != "o" {
		t.Fatalf("sans record_input, aucune saisie ne doit être gardée: %+v %v", list[0], kinds)
	}
}

func TestRecordingKeepsInputAndMasksSecrets(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	rec := st.Start("alice", "srv", "ssh", "")
	rec.CaptureInput()
	rec.Output([]byte("alice@srv:~$ "))
	rec.Input([]byte("su"))
	rec.Input([]byte("do ls\r"))
	rec.Output([]byte("su\r\n[sudo] password for alice: "))
	rec.Input([]byte("h"))
	rec.Input([]byte("unter2"))
	rec.Input([]byte("\r"))
	rec.Output([]byte("\r\nfile\r\nalice@srv:~$ "))
	rec.Input([]byte("echo après\r"))
	rec.Output([]byte("Enter passphrase for key '/home/a/.ssh/id': "))
	rec.Input([]byte("abc\x03"))
	rec.Input([]byte("whoami\r"))
	rec.Close()

	list, _ := st.List()
	if !list[0].Input {
		t.Fatal("la méta doit indiquer que la saisie est enregistrée")
	}
	_, inputs := castKinds(t, st, list[0].ID)
	if strings.Contains(inputs, "hunter2") || strings.Contains(inputs, "abc") || strings.Contains(inputs, "unter") {
		t.Fatalf("un secret a été enregistré: %q", inputs)
	}
	for _, want := range []string{"sudo ls\r", "[masqué]", "echo après\r", "whoami\r"} {
		if !strings.Contains(inputs, want) {
			t.Errorf("la saisie %q manque: %q", want, inputs)
		}
	}
	if strings.Count(inputs, "[masqué]") != 2 {
		t.Errorf("un marqueur par invite attendu: %q", inputs)
	}
}

func TestRecordingInputIsNilSafe(t *testing.T) {
	var rec *Recording
	rec.CaptureInput()
	rec.Input([]byte("x"))
}

func TestPolicyRecordInputNeedsRecording(t *testing.T) {
	if err := (Policy{RecordInput: true}).Validate(); err == nil {
		t.Fatal("record_input sans record_sessions doit être refusé")
	}
	if err := (Policy{RecordSessions: true, RecordInput: true}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTouchRWRecordsWhatTheUserTypes(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	rec := st.Start("alice", "srv", "web", "")
	rec.CaptureInput()
	live := NewLiveRegistry().Track("alice", "srv", "web", "", func() {})
	defer live.Done()
	rw := touchRW{ReadWriteCloser: nopRWC{strings.NewReader("pwd\r")}, h: live, rec: rec}
	buf := make([]byte, 16)
	if _, err := rw.Read(buf); err != nil {
		t.Fatal(err)
	}
	rec.Close()
	list, _ := st.List()
	if _, inputs := castKinds(t, st, list[0].ID); inputs != "pwd\r" {
		t.Fatalf("saisie enregistrée: %q", inputs)
	}
}

type nopRWC struct{ *strings.Reader }

func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }
