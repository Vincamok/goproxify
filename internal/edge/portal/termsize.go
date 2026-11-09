// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// Taille du terminal web. Le navigateur dimensionne xterm.js à son conteneur ; sans le dire à la machine distante, son PTY
// reste à la taille par défaut : les lignes ne passent pas à la ligne au bon endroit, `ls` met en colonnes pour une autre
// largeur, un éditeur plein écran dessine hors de la zone visible, et le prompt peut tomber sous le bas de l'écran.
//
// Le navigateur envoie la taille dans un message texte `\x00gpx-resize:<colonnes>x<lignes>`. Le préfixe commence par un octet nul
// qu'un utilisateur ne tape pas, et ces messages ne sont jamais transmis à l'entrée de la machine distante.

const resizeMarker = "\x00gpx-resize:"

const (
	minCols, maxCols = 20, 500
	minRows, maxRows = 5, 200
	// Taille que prend le PTY quand le navigateur n'a rien annoncé (client ancien, message perdu).
	defaultCols, defaultRows = 120, 40
	// initialSizeWait : combien de temps on attend la taille du navigateur avant d'ouvrir le PTY.
	initialSizeWait = 750 * time.Millisecond
)

// parseResizeFrame lit un message de redimensionnement ; ok faux : c'est de la saisie ordinaire, ou une taille hors bornes.
func parseResizeFrame(data []byte) (cols, rows int, ok bool) {
	s := string(data)
	if !strings.HasPrefix(s, resizeMarker) {
		return 0, 0, false
	}
	c, r, found := strings.Cut(strings.TrimPrefix(s, resizeMarker), "x")
	if !found {
		return 0, 0, false
	}
	cols, err1 := strconv.Atoi(strings.TrimSpace(c))
	rows, err2 := strconv.Atoi(strings.TrimSpace(r))
	if err1 != nil || err2 != nil || cols < minCols || cols > maxCols || rows < minRows || rows > maxRows {
		return 0, 0, false
	}
	return cols, rows, true
}

// termSizer est implémenté par les flux qui connaissent la taille du terminal du navigateur.
type termSizer interface {
	// InitialSize attend au plus wait la première taille annoncée ; faux : le navigateur n'a rien dit.
	InitialSize(wait time.Duration) (cols, rows int, ok bool)
	// OnResize enregistre ce qui s'applique à chaque changement de taille ultérieur.
	OnResize(fn func(cols, rows int))
}

// wsRW ponte une connexion WebSocket vers un flux d'octets. Une goroutine lit la connexion en continu : elle sépare les messages
// de redimensionnement de la saisie, et laisse attendre la première taille sans fermer la connexion (annuler un contexte de
// lecture la ferme).
type wsRW struct {
	ctx context.Context
	c   *websocket.Conn

	in   chan []byte
	rest []byte
	err  error

	mu      sync.Mutex
	cols    int
	rows    int
	changed chan struct{}
	onSize  func(cols, rows int)
	// applied : la taille que le PTY distant a déjà reçue (celle de InitialSize, puis chaque changement transmis).
	appliedCols, appliedRows int
}

func newWSRW(ctx context.Context, c *websocket.Conn) *wsRW {
	w := &wsRW{ctx: ctx, c: c, in: make(chan []byte, 256), changed: make(chan struct{}, 1)}
	go w.pump()
	return w
}

func (w *wsRW) pump() {
	defer close(w.in)
	for {
		_, data, err := w.c.Read(w.ctx)
		if err != nil {
			w.mu.Lock()
			w.err = err
			w.mu.Unlock()
			return
		}
		if cols, rows, ok := parseResizeFrame(data); ok {
			w.setSize(cols, rows)
			continue
		}
		select {
		case w.in <- data:
		case <-w.ctx.Done():
			return
		}
	}
}

func (w *wsRW) setSize(cols, rows int) {
	w.mu.Lock()
	w.cols, w.rows = cols, rows
	fn := w.onSize
	if fn != nil {
		w.appliedCols, w.appliedRows = cols, rows
	}
	w.mu.Unlock()
	select {
	case w.changed <- struct{}{}:
	default:
	}
	if fn != nil {
		fn(cols, rows)
	}
}

// InitialSize : voir termSizer.
func (w *wsRW) InitialSize(wait time.Duration) (int, int, bool) {
	w.mu.Lock()
	cols, rows := w.cols, w.rows
	w.mu.Unlock()
	if cols == 0 {
		select {
		case <-w.changed:
		case <-time.After(wait):
		}
		w.mu.Lock()
		cols, rows = w.cols, w.rows
		w.mu.Unlock()
	}
	if cols > 0 {
		w.mu.Lock()
		w.appliedCols, w.appliedRows = cols, rows
		w.mu.Unlock()
	}
	return cols, rows, cols > 0
}

// OnResize : voir termSizer. Entre l'ouverture du PTY et cet appel, le navigateur a pu redimensionner la fenêtre : la dernière
// taille connue, si elle diffère de celle que le PTY a reçue, est appliquée aussitôt plutôt que perdue.
func (w *wsRW) OnResize(fn func(cols, rows int)) {
	w.mu.Lock()
	w.onSize = fn
	cols, rows := w.cols, w.rows
	stale := cols > 0 && (cols != w.appliedCols || rows != w.appliedRows)
	if stale {
		w.appliedCols, w.appliedRows = cols, rows
	}
	w.mu.Unlock()
	if stale && fn != nil {
		fn(cols, rows)
	}
}

func (w *wsRW) Read(p []byte) (int, error) {
	if len(w.rest) == 0 {
		data, ok := <-w.in
		if !ok {
			w.mu.Lock()
			err := w.err
			w.mu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		w.rest = data
	}
	n := copy(p, w.rest)
	w.rest = w.rest[n:]
	return n, nil
}

func (w *wsRW) Write(p []byte) (int, error) {
	err := w.c.Write(w.ctx, websocket.MessageBinary, p)
	return len(p), err
}

func (w *wsRW) Close() error {
	return w.c.Close(websocket.StatusNormalClosure, "")
}
