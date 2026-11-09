// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"nhooyr.io/websocket"
)

func TestParseResizeFrame(t *testing.T) {
	good := map[string][2]int{
		"\x00gpx-resize:120x40":  {120, 40},
		"\x00gpx-resize: 80x24":  {80, 24},
		"\x00gpx-resize:500x200": {500, 200},
	}
	for in, want := range good {
		c, r, ok := parseResizeFrame([]byte(in))
		if !ok || c != want[0] || r != want[1] {
			t.Errorf("%q : %d %d %v", in, c, r, ok)
		}
	}
	for _, in := range []string{
		"", "ls -la\n", "gpx-resize:120x40", " \x00gpx-resize:120x40", "echo \x00gpx-resize:120x40",
		"\x00gpx-resize:", "\x00gpx-resize:120", "\x00gpx-resize:axb", "\x00gpx-resize:0x0", "\x00gpx-resize:10x40",
		"\x00gpx-resize:120x2", "\x00gpx-resize:9999x40", "\x00gpx-resize:120x9999", "\x00gpx-resize:-5x40",
	} {
		if _, _, ok := parseResizeFrame([]byte(in)); ok {
			t.Errorf("%q ne doit pas être pris pour un redimensionnement", in)
		}
	}
}

// wsPair ouvre une vraie connexion WebSocket : le côté serveur est enveloppé par newWSRW, le côté client est rendu tel quel.
func wsPair(t *testing.T) (*wsRW, *websocket.Conn) {
	t.Helper()
	ready := make(chan *wsRW, 1)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ready <- newWSRW(r.Context(), c)
		<-done
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	select {
	case rw := <-ready:
		return rw, c
	case <-time.After(5 * time.Second):
		t.Fatal("serveur WebSocket non prêt")
		return nil, nil
	}
}

func TestWSRWSeparatesResizeFramesFromTyping(t *testing.T) {
	rw, c := wsPair(t)
	ctx := context.Background()
	var mu sync.Mutex
	var seen [][2]int
	rw.OnResize(func(cols, rows int) { mu.Lock(); seen = append(seen, [2]int{cols, rows}); mu.Unlock() })

	_ = c.Write(ctx, websocket.MessageText, []byte("ls\n"))
	_ = c.Write(ctx, websocket.MessageText, []byte("\x00gpx-resize:100x30"))
	_ = c.Write(ctx, websocket.MessageText, []byte("echo \x00gpx-resize:1x1\n")) // saisie ordinaire : le préfixe n'est pas en tête
	_ = c.Write(ctx, websocket.MessageText, []byte("\x00gpx-resize:90x25"))
	_ = c.Write(ctx, websocket.MessageText, []byte("fin"))

	buf := make([]byte, 64)
	var typed strings.Builder
	for _, want := range []string{"ls\n", "echo \x00gpx-resize:1x1\n", "fin"} {
		n, err := rw.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("saisie attendue %q, obtenu %q (%v)", want, buf[:n], err)
		}
		typed.Write(buf[:n])
	}
	if strings.Contains(strings.ReplaceAll(typed.String(), "echo \x00gpx-resize:1x1\n", ""), "gpx-resize") {
		t.Fatal("un message de redimensionnement ne doit jamais atteindre l'entrée de la machine distante")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != [2]int{100, 30} || seen[1] != [2]int{90, 25} {
		t.Fatalf("tailles vues : %v", seen)
	}
}

func TestWSRWWaitsForTheFirstSizeThenFallsBack(t *testing.T) {
	rw, c := wsPair(t)
	if _, _, ok := rw.InitialSize(60 * time.Millisecond); ok {
		t.Fatal("aucune taille annoncée : la valeur par défaut s'applique")
	}
	go func() {
		time.Sleep(80 * time.Millisecond)
		_ = c.Write(context.Background(), websocket.MessageText, []byte("\x00gpx-resize:110x33"))
	}()
	cols, rows, ok := rw.InitialSize(3 * time.Second)
	if !ok || cols != 110 || rows != 33 {
		t.Fatalf("première taille : %d %d %v", cols, rows, ok)
	}
	if cols2, rows2, ok := rw.InitialSize(time.Second); !ok || cols2 != 110 || rows2 != 33 {
		t.Fatalf("une taille déjà connue se rend aussitôt : %d %d %v", cols2, rows2, ok)
	}
}

func TestWSRWKeepsDataLargerThanTheReadBuffer(t *testing.T) {
	rw, c := wsPair(t)
	payload := strings.Repeat("abcdefghij", 50) // 500 octets lus par morceaux de 64
	_ = c.Write(context.Background(), websocket.MessageText, []byte(payload))
	var got strings.Builder
	buf := make([]byte, 64)
	for got.Len() < len(payload) {
		n, err := rw.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	if got.String() != payload {
		t.Fatal("une saisie plus grande que le tampon de lecture ne doit pas être tronquée")
	}
}

func TestWSRWReadReturnsAnErrorWhenTheBrowserLeaves(t *testing.T) {
	rw, c := wsPair(t)
	c.Close(websocket.StatusNormalClosure, "")
	done := make(chan error, 1)
	go func() { _, err := rw.Read(make([]byte, 8)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("la fin de la connexion doit remonter")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read bloque après la fermeture")
	}
}

// --- le pont SSH reçoit la bonne taille -------------------------------------------------------------------------------

type ptyRecord struct {
	mu          sync.Mutex
	cols, rows  uint32
	resizes     [][2]uint32
	gotShell    chan struct{}
	resizedOnce chan struct{}
}

// startFakeSSH lance un serveur SSH qui accepte tout, note la taille du PTY et ses changements, et répond à l'entrée.
func startFakeSSH(t *testing.T) (string, int, *ptyRecord) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	rec := &ptyRecord{gotShell: make(chan struct{}), resizedOnce: make(chan struct{})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							switch r.Type {
							case "pty-req":
								var p struct {
									Term     string
									W, H     uint32
									Wpx, Hpx uint32
									Modes    string
								}
								_ = ssh.Unmarshal(r.Payload, &p)
								rec.mu.Lock()
								rec.cols, rec.rows = p.W, p.H
								rec.mu.Unlock()
								_ = r.Reply(true, nil)
							case "window-change":
								var p struct{ W, H, Wpx, Hpx uint32 }
								_ = ssh.Unmarshal(r.Payload, &p)
								rec.mu.Lock()
								rec.resizes = append(rec.resizes, [2]uint32{p.W, p.H})
								rec.mu.Unlock()
								select {
								case rec.resizedOnce <- struct{}{}:
								default:
								}
							case "shell":
								_ = r.Reply(true, nil)
								close(rec.gotShell)
								_, _ = ch.Write([]byte("prompt$ "))
							default:
								_ = r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port, rec
}

// sizedPipe est un flux de navigateur : une taille initiale, des changements à la demande, et rien à lire.
type sizedPipe struct {
	io.ReadWriteCloser
	initial [2]int
	mu      sync.Mutex
	fn      func(cols, rows int)
	ready   chan struct{} // fermé quand le pont a enregistré son rappel
	once    sync.Once
}

func (s *sizedPipe) InitialSize(time.Duration) (int, int, bool) {
	return s.initial[0], s.initial[1], s.initial[0] > 0
}
func (s *sizedPipe) OnResize(fn func(cols, rows int)) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
}
func (s *sizedPipe) resize(cols, rows int) {
	s.mu.Lock()
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		fn(cols, rows)
	}
}

type pipeRW struct {
	r   *io.PipeReader
	w   *io.PipeWriter
	out chan []byte
}

func (p *pipeRW) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *pipeRW) Write(b []byte) (int, error) {
	c := append([]byte(nil), b...)
	select {
	case p.out <- c:
	default:
	}
	return len(b), nil
}
func (p *pipeRW) Close() error { _ = p.r.Close(); return p.w.Close() }

func TestBridgeWebSSHOpensThePTYAtTheBrowserSizeAndFollowsResizes(t *testing.T) {
	host, port, rec := startFakeSSH(t)
	pr, pw := io.Pipe()
	rw := &sizedPipe{ReadWriteCloser: &pipeRW{r: pr, w: pw, out: make(chan []byte, 16)}, initial: [2]int{97, 31}, ready: make(chan struct{})}
	errc := make(chan error, 1)
	go func() {
		errc <- BridgeWebSSH(dialTarget{Kind: TargetSSH, Host: host, Port: port, Username: "u", Password: "p"}, rw)
	}()

	select {
	case <-rec.gotShell:
	case err := <-errc:
		t.Fatalf("pont : %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("pas de shell")
	}
	rec.mu.Lock()
	if rec.cols != 97 || rec.rows != 31 {
		t.Fatalf("le PTY doit prendre la taille du navigateur (97x31), obtenu %dx%d", rec.cols, rec.rows)
	}
	rec.mu.Unlock()

	select {
	case <-rw.ready: // le pont suit les changements de taille à partir de là
	case <-time.After(5 * time.Second):
		t.Fatal("le pont n'a pas enregistré son suivi de taille")
	}
	rw.resize(140, 45)
	select {
	case <-rec.resizedOnce:
	case <-time.After(5 * time.Second):
		t.Fatal("le changement de taille n'est pas parvenu à la machine distante")
	}
	rec.mu.Lock()
	if len(rec.resizes) != 1 || rec.resizes[0] != [2]uint32{140, 45} {
		t.Fatalf("window-change : %v", rec.resizes)
	}
	rec.mu.Unlock()
	_ = pw.Close()
}

func TestBridgeWebSSHFallsBackToTheDefaultSizeWithoutABrowserSize(t *testing.T) {
	host, port, rec := startFakeSSH(t)
	pr, pw := io.Pipe()
	rw := &pipeRW{r: pr, w: pw, out: make(chan []byte, 16)} // ni InitialSize ni OnResize : client ancien
	go func() {
		_ = BridgeWebSSH(dialTarget{Kind: TargetSSH, Host: host, Port: port, Username: "u", Password: "p"}, rw)
	}()
	select {
	case <-rec.gotShell:
	case <-time.After(10 * time.Second):
		t.Fatal("pas de shell")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.cols != defaultCols || rec.rows != defaultRows {
		t.Fatalf("taille par défaut attendue %dx%d, obtenu %dx%d", defaultCols, defaultRows, rec.cols, rec.rows)
	}
	_ = pw.Close()
}

func TestTerminalUIKeepsPaddingOffTheMeasuredElementAndReportsItsSize(t *testing.T) {
	for _, frag := range []string{
		`<div id="termBox"><div id="term"></div></div>`, // xterm mesure #term : pas de marge ni de bordure dessus
		`#termBox {`,
		`sendTermSize`,
		`\x00gpx-resize:`,
	} {
		if !strings.Contains(portalIndexHTML, frag) {
			t.Errorf("l'interface du terminal doit contenir %q", frag)
		}
	}
	css := portalIndexHTML[strings.Index(portalIndexHTML, "#term {"):]
	css = css[:strings.Index(css, "}")]
	if strings.Contains(css, "padding") || strings.Contains(css, "border") {
		t.Fatalf("#term ne doit porter ni padding ni bordure (sous border-box, ils comptent dans la hauteur que xterm mesure) : %s", css)
	}
}

// Entre l'ouverture du PTY et l'enregistrement du suivi, le navigateur peut redimensionner la fenêtre : cette taille ne doit
// pas être perdue.
func TestWSRWReplaysASizeThatArrivedBeforeTheBridgeWasListening(t *testing.T) {
	rw, c := wsPair(t)
	ctx := context.Background()
	_ = c.Write(ctx, websocket.MessageText, []byte("\x00gpx-resize:100x30"))
	if cols, rows, ok := rw.InitialSize(3 * time.Second); !ok || cols != 100 || rows != 30 {
		t.Fatalf("taille initiale : %d %d %v", cols, rows, ok)
	}
	// Le PTY est ouvert à 100x30 ; la fenêtre change avant que le pont n'écoute.
	_ = c.Write(ctx, websocket.MessageText, []byte("\x00gpx-resize:90x25"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rw.mu.Lock()
		got := rw.cols == 90
		rw.mu.Unlock()
		if got {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := make(chan [2]int, 4)
	rw.OnResize(func(cols, rows int) { got <- [2]int{cols, rows} })
	select {
	case s := <-got:
		if s != [2]int{90, 25} {
			t.Fatalf("taille rejouée : %v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("la taille arrivée avant l'enregistrement a été perdue")
	}

	// Une taille identique à celle du PTY n'est pas rejouée.
	rw2, c2 := wsPair(t)
	_ = c2.Write(ctx, websocket.MessageText, []byte("\x00gpx-resize:100x30"))
	rw2.InitialSize(3 * time.Second)
	called := make(chan struct{}, 1)
	rw2.OnResize(func(int, int) { called <- struct{}{} })
	select {
	case <-called:
		t.Fatal("aucun changement : rien à rejouer")
	case <-time.After(150 * time.Millisecond):
	}
}
