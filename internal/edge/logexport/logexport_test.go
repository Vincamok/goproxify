// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

const pw = "un-mot-de-passe-solide"

func TestEncryptRoundTripAcrossManyChunks(t *testing.T) {
	plain := make([]byte, 3*chunkSize+777)
	_, _ = rand.Read(plain)
	var buf bytes.Buffer
	w, err := NewEncryptWriter(&buf, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sealed := buf.Bytes()
	if bytes.Contains(sealed, plain[:64]) {
		t.Fatal("le contenu apparaît en clair")
	}
	r, err := NewDecryptReader(bytes.NewReader(sealed), pw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("aller-retour : %d octets, %v", len(got), err)
	}

	// Un contenu vide est valide, et un multiple exact de la taille de bloc aussi.
	for _, n := range []int{0, chunkSize} {
		var b bytes.Buffer
		w, _ := NewEncryptWriter(&b, pw)
		_, _ = w.Write(make([]byte, n))
		_ = w.Close()
		r, _ := NewDecryptReader(&b, pw)
		if got, err := io.ReadAll(r); err != nil || len(got) != n {
			t.Errorf("%d octets : %d relus, %v", n, len(got), err)
		}
	}
}

func TestDecryptRefusesWrongPasswordTamperingTruncationAndReordering(t *testing.T) {
	plain := bytes.Repeat([]byte("ligne de log\n"), 20000) // ~260 Kio : cinq blocs
	var buf bytes.Buffer
	w, _ := NewEncryptWriter(&buf, pw)
	_, _ = w.Write(plain)
	_ = w.Close()
	sealed := buf.Bytes()

	read := func(data []byte, password string) error {
		r, err := NewDecryptReader(bytes.NewReader(data), password)
		if err != nil {
			return err
		}
		_, err = io.ReadAll(r)
		return err
	}
	if err := read(sealed, "un-autre-mot-de-passe"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("mauvais mot de passe : %v", err)
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)/2] ^= 1
	if err := read(flipped, pw); err == nil {
		t.Error("un octet modifié est accepté")
	}
	// Fin coupée au bord d'un bloc : le bloc final manque.
	headerLen := len(magic) + 1 + saltSize
	blockLen := 4 + chunkSize + 16
	if err := read(sealed[:headerLen+2*blockLen], pw); err == nil {
		t.Error("un fichier coupé entre deux blocs est accepté")
	}
	if err := read(sealed[:len(sealed)-5], pw); err == nil {
		t.Error("un fichier tronqué est accepté")
	}
	// Deux blocs échangés.
	swapped := append([]byte(nil), sealed...)
	a, b := swapped[headerLen:headerLen+blockLen], swapped[headerLen+blockLen:headerLen+2*blockLen]
	tmp := append([]byte(nil), a...)
	copy(a, b)
	copy(b, tmp)
	if err := read(swapped, pw); err == nil {
		t.Error("des blocs échangés sont acceptés")
	}
	if err := read(append(append([]byte(nil), sealed...), 'x'), pw); err == nil {
		t.Error("des octets ajoutés après le dernier bloc sont acceptés")
	}
	if _, err := NewEncryptWriter(io.Discard, "court"); err == nil {
		t.Error("un mot de passe trop court est accepté")
	}
	if _, err := NewDecryptReader(strings.NewReader("pas un export"), pw); err == nil {
		t.Error("un fichier quelconque est accepté")
	}
}

type memSealer struct {
	files map[string][]byte
	fail  bool
}

func (m *memSealer) SaveFile(path string, v any) error {
	b, err := json.Marshal(v)
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	m.files[path] = b
	return err
}

func (m *memSealer) LoadFile(path string, v any) (bool, error) {
	if m.fail {
		return false, errors.New("secret d'appairage changé")
	}
	b, ok := m.files[path]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, v)
}

func TestSigningKeyIsCreatedOnceAndNeverOverwritten(t *testing.T) {
	s := &memSealer{}
	k1, err := LoadOrCreateKey(s, "sign.gpx")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(s, "sign.gpx")
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("la clé change d'un appel à l'autre : %v", err)
	}
	before := string(s.files["sign.gpx"])
	s.fail = true
	if _, err := LoadOrCreateKey(s, "sign.gpx"); err == nil {
		t.Fatal("une clé illisible doit être une erreur, pas une clé neuve")
	}
	s.fail = false
	if string(s.files["sign.gpx"]) != before {
		t.Fatal("la clé a été écrasée")
	}
}

func TestManifestSignatureDetectsAnyChangeAndPinsTheKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Version: 1, Node: "gw-a", Rows: 12, Reason: "réquisition <2026/1234> & co"}
	file, err := SignManifest(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseManifest(file, nil)
	if err != nil || got.Rows != 12 || got.Reason != m.Reason || got.KeyID != KeyID(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("ParseManifest = %+v, %v", got, err)
	}
	if _, err := ParseManifest(file, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("clé attendue refusée : %v", err)
	}
	if _, err := ParseManifest(file, other.Public().(ed25519.PublicKey)); err == nil {
		t.Error("une autre clé attendue doit être refusée")
	}
	if _, err := ParseManifest(bytes.Replace(file, []byte(`"rows": 12`), []byte(`"rows": 13`), 1), nil); err == nil {
		t.Error("un manifeste modifié est accepté")
	}
	// Un attaquant qui remplace la clé publique et re-signe est écarté par la clé attendue, pas par la signature.
	forged, _ := SignManifest(other, Manifest{Version: 1, Rows: 12})
	if _, err := ParseManifest(forged, nil); err != nil {
		t.Errorf("un manifeste cohérent est lisible sans clé attendue : %v", err)
	}
	if _, err := ParseManifest(forged, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Error("un manifeste signé par une autre clé passe la clé attendue")
	}
	// La signature résiste à la réindentation du fichier.
	var s Signed
	_ = json.Unmarshal(file, &s)
	pretty, _ := json.Marshal(s)
	if _, err := ParseManifest(pretty, nil); err != nil {
		t.Errorf("manifeste recompacté : %v", err)
	}
}

func at(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

func newStore(t *testing.T) *logstore.Store {
	t.Helper()
	k, _ := ipcrypt.NewKey()
	s, err := logstore.Open(logstore.Options{Dir: filepath.Join(t.TempDir(), "logs"), IPKey: k})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

const realIP = "203.0.113.42"

func fill(s *logstore.Store) {
	e := func(ts, domain, ip, path string) logstore.Entry {
		return logstore.Entry{Ts: at(ts), Level: "info", Component: "edge", Domain: domain, Method: "GET", Path: path, Status: 200, IP: ip, UserAgent: "curl/8", RequestID: "r"}
	}
	s.Add(logstore.KindAccess, e("2026-10-19T10:00:00Z", "a.example", "198.51.100.1", "/avant"))
	p := e("2026-10-20T10:00:00Z", "a.example", "203.0.113.0", "/pseudo")
	p.RealIP, p.IPTruncated = realIP, true
	s.Add(logstore.KindAccess, p)
	s.Add(logstore.KindAccess, e("2026-10-21T10:00:00Z", "b.example", "198.51.100.9", `=HYPERLINK("http://evil")`))
	s.Add(logstore.KindAccess, e("2026-12-01T10:00:00Z", "a.example", "198.51.100.1", "/apres"))
	s.Flush()
}

func request(format, password string) Request {
	return Request{Node: "gw-a", Operator: "alice", Reason: "réquisition 2026/1234", Kind: logstore.KindAccess,
		From: at("2026-10-20T00:00:00Z"), To: at("2026-11-01T00:00:00Z"), Format: format, Password: password}
}

func TestExportWritesSignedEncryptedNDJSONWithTheRealIP(t *testing.T) {
	s := newStore(t)
	fill(s)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	now := func() time.Time { return at("2026-11-02T09:00:00Z") }

	req := request(FormatNDJSON, pw)
	res, err := Run(s, priv, req, filepath.Join(dir, "export"), now)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.DataPath) != "export.ndjson.gpxe" || filepath.Base(res.ManifestPath) != "export.manifest.json" {
		t.Fatalf("fichiers : %s, %s", res.DataPath, res.ManifestPath)
	}
	m := res.Manifest
	if m.Rows != 2 || !m.Encrypted || m.Operator != "alice" || m.CreatedAt != "2026-11-02T09:00:00Z" || m.Kind != "access" {
		t.Fatalf("manifeste = %+v", m)
	}
	// Ni l'IP réelle ni le contenu ne sont lisibles sans le mot de passe ; le manifeste ne porte aucune IP.
	for _, p := range []string{res.DataPath, res.ManifestPath} {
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte(realIP)) || bytes.Contains(raw, []byte("/pseudo")) {
			t.Errorf("%s laisse lire des données", filepath.Base(p))
		}
	}

	var plain bytes.Buffer
	rep, err := Verify(res.ManifestPath, res.DataPath, pw, priv.Public().(ed25519.PublicKey), &plain)
	if err != nil || !rep.FileChecked || !rep.PlainChecked {
		t.Fatalf("Verify = %+v, %v", rep, err)
	}
	lines := strings.Split(strings.TrimSpace(plain.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lignes : %v", lines)
	}
	var first map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first["ip"] != realIP || first["ip_pseudonymized"] != true || first["ip_truncated"] != nil || first["id"] == "" || !strings.HasPrefix(first["id"].(string), "gw-a:access:") {
		t.Errorf("ligne pseudonymisée exportée = %v", first)
	}
	if strings.Contains(plain.String(), "/avant") || strings.Contains(plain.String(), "/apres") {
		t.Error("des lignes hors plage sont exportées")
	}

	// Une modification du fichier remis, ou du manifeste, ou un mauvais mot de passe, sont refusés.
	raw, _ := os.ReadFile(res.DataPath)
	raw[len(raw)/2] ^= 1
	bad := filepath.Join(dir, "bad.gpxe")
	_ = os.WriteFile(bad, raw, 0o600)
	if _, err := Verify(res.ManifestPath, bad, pw, nil, nil); err == nil {
		t.Error("un fichier modifié passe la vérification")
	}
	if _, err := Verify(res.ManifestPath, res.DataPath, "un-autre-mot-de-passe", nil, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("mauvais mot de passe : %v", err)
	}
	if rep, err := Verify(res.ManifestPath, res.DataPath, "", nil, nil); err != nil || !rep.FileChecked || rep.PlainChecked {
		t.Errorf("sans mot de passe : %+v, %v", rep, err)
	}
	// Un export n'en écrase pas un autre.
	if _, err := Run(s, priv, req, filepath.Join(dir, "export"), now); err == nil {
		t.Error("un export existant a été écrasé")
	}
}

func TestExportFiltersByIPAndDomainAndRecordsOnlyAHashOfTheIP(t *testing.T) {
	s := newStore(t)
	fill(s)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	now := func() time.Time { return at("2026-11-02T09:00:00Z") }

	req := request(FormatNDJSON, "")
	req.IP = realIP
	res, err := Run(s, priv, req, filepath.Join(dir, "par-ip"), now)
	if err != nil || res.Manifest.Rows != 1 || res.Manifest.Encrypted {
		t.Fatalf("export par IP : %+v, %v", res.Manifest, err)
	}
	manifest, _ := os.ReadFile(res.ManifestPath)
	if bytes.Contains(manifest, []byte(realIP)) || res.Manifest.Filters.IPSHA256 == "" {
		t.Error("le manifeste doit porter l'empreinte de l'IP filtrée, pas l'IP")
	}
	if rep, err := Verify(res.ManifestPath, res.DataPath, "", nil, nil); err != nil || !rep.PlainChecked {
		t.Errorf("vérification d'un export en clair : %+v, %v", rep, err)
	}

	req = request(FormatNDJSON, "")
	req.Domain = "b.example"
	if res, err := Run(s, priv, req, filepath.Join(dir, "par-domaine"), now); err != nil || res.Manifest.Rows != 1 || res.Manifest.Filters.Domain != "b.example" {
		t.Fatalf("export par domaine : %+v, %v", res, err)
	}

	req = request(FormatNDJSON, "")
	req.From, req.To = at("2030-01-01T00:00:00Z"), at("2030-02-01T00:00:00Z")
	if res, err := Run(s, priv, req, filepath.Join(dir, "vide"), now); err != nil || res.Manifest.Rows != 0 || res.Manifest.FirstTS != "" {
		t.Fatalf("export vide : %+v, %v", res, err)
	}
	req.IP = "pas une ip"
	if _, err := Run(s, priv, req, filepath.Join(dir, "invalide"), now); err == nil {
		t.Error("une IP invalide est acceptée")
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, "invalide*")); len(entries) != 0 {
		t.Errorf("fichiers laissés après un échec : %v", entries)
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".export-*")); len(entries) != 0 {
		t.Errorf("fichiers temporaires laissés : %v", entries)
	}
}

func TestCSVExportNeutralizesFormulasAndKeepsTheHeader(t *testing.T) {
	s := newStore(t)
	fill(s)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	res, err := Run(s, priv, request(FormatCSV, ""), filepath.Join(dir, "export"), func() time.Time { return at("2026-11-02T09:00:00Z") })
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(res.DataPath)
	text := string(raw)
	if !strings.HasPrefix(text, "id,ts,level,") || !strings.Contains(text, `'=HYPERLINK`) || strings.Contains(text, `,=HYPERLINK`) {
		t.Fatalf("CSV :\n%s", text)
	}
	if !strings.Contains(text, realIP) {
		t.Error("l'IP réelle manque du CSV")
	}
}

func TestExportNeedsAReasonAValidRangeAndKnownFormat(t *testing.T) {
	s := newStore(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	now := func() time.Time { return time.Now() }
	mut := map[string]func(*Request){
		"sans motif":     func(r *Request) { r.Reason = " " },
		"plage inversée": func(r *Request) { r.From, r.To = r.To, r.From },
		"format":         func(r *Request) { r.Format = "xml" },
		"type":           func(r *Request) { r.Kind = "audit" },
		"mot de passe":   func(r *Request) { r.Password = "court" },
	}
	for name, m := range mut {
		req := request(FormatNDJSON, "")
		m(&req)
		if _, err := Run(s, priv, req, filepath.Join(dir, "x"), now); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, "*")); len(entries) != 0 {
		t.Errorf("fichiers laissés : %v", entries)
	}
}

func TestAuditChainDetectsARemovedOrChangedLine(t *testing.T) {
	a := Audit{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
	if entries, err := a.Read(); err != nil || len(entries) != 0 {
		t.Fatalf("journal absent : %v, %v", entries, err)
	}
	now := at("2026-11-02T09:00:00Z")
	for i, op := range []string{"export", "hold_add", "hold_release"} {
		if err := a.Append(now.Add(time.Duration(i)*time.Minute), "alice", op, map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := a.Read()
	if err != nil || len(entries) != 3 || entries[1].Op != "hold_add" || entries[0].Prev != "" || entries[2].Operator != "alice" {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	raw, _ := os.ReadFile(a.Path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	_ = os.WriteFile(a.Path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600) // ligne du milieu retirée
	if _, err := a.Read(); err == nil || !strings.Contains(err.Error(), "chaîne") {
		t.Errorf("ligne retirée : %v", err)
	}
	_ = os.WriteFile(a.Path, []byte(strings.Replace(lines[0], "alice", "bob", 1)+"\n"+lines[1]+"\n"), 0o600) // première ligne modifiée
	if _, err := a.Read(); err == nil {
		t.Error("ligne modifiée non détectée")
	}
}

func TestPublicKeyInManifestMatchesKeyID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	file, _ := SignManifest(priv, Manifest{Version: 1})
	m, err := ParseManifest(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(m.PublicKey)
	if KeyID(ed25519.PublicKey(pub)) != m.KeyID || len(m.KeyID) != 32 {
		t.Fatalf("KeyID = %q", m.KeyID)
	}
}
