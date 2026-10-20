// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultLogCursorsPath : position de lecture des logs de chaque conteneur, sur le volume de l'Agent.
	DefaultLogCursorsPath = "/etc/goproxify/log-cursors.json"

	// logCursorMaxAge : un conteneur qu'on n'a pas suivi depuis ce délai est oublié (il a été recréé sous un autre ID).
	logCursorMaxAge = 30 * 24 * time.Hour
)

// LogForwarder collecte les logs des conteneurs labellisés et les transmet à la passerelle.
//
// Docker garde les lignes ; l'Agent ne retient que la position atteinte, qu'il n'avance qu'une fois la passerelle
// ayant accusé réception d'un lot. Une passerelle injoignable, un redémarrage de l'Agent ou un envoi refusé ne
// perdent donc rien : la lecture reprend à la position enregistrée (option since de l'API Docker).
type LogForwarder struct {
	client        *Client
	follow        func(ctx context.Context, path string, fn func([]byte)) error
	adminEndpoint string
	authToken     string
	bufferLines   int
	log           *slog.Logger
	httpClient    *http.Client

	flushEvery time.Duration
	retryMin   time.Duration
	retryMax   time.Duration

	mu        sync.Mutex
	watching  map[string]context.CancelFunc // containerID → cancel
	cursors   map[string]time.Time          // containerID → première ligne pas encore acquittée
	statePath string
}

// NewLogForwarder crée un LogForwarder.
func NewLogForwarder(client *Client, adminEndpoint, authToken string, bufferLines int, log *slog.Logger) *LogForwarder {
	if bufferLines <= 0 {
		bufferLines = 500
	}
	f := &LogForwarder{
		client:        client,
		adminEndpoint: adminEndpoint,
		authToken:     authToken,
		bufferLines:   bufferLines,
		log:           log,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		flushEvery:    5 * time.Second,
		retryMin:      2 * time.Second,
		retryMax:      30 * time.Second,
		watching:      make(map[string]context.CancelFunc),
		cursors:       make(map[string]time.Time),
	}
	if client != nil {
		f.follow = client.StreamLines
	}
	f.SetStatePath(DefaultLogCursorsPath)
	return f
}

// SetStatePath change le fichier des positions et le relit. Vide : positions gardées en mémoire seulement.
func (f *LogForwarder) SetStatePath(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statePath = path
	f.cursors = make(map[string]time.Time)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var raw map[string]time.Time
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	cutoff := time.Now().Add(-logCursorMaxAge)
	for id, t := range raw {
		if t.After(cutoff) {
			f.cursors[id] = t
		}
	}
}

// Watch démarre le suivi des logs d'un conteneur.
func (f *LogForwarder) Watch(ctx context.Context, containerID, containerName string) {
	f.mu.Lock()
	if _, ok := f.watching[containerID]; ok {
		f.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	f.watching[containerID] = cancel
	f.mu.Unlock()

	go f.stream(cctx, containerID, containerName)
}

// Unwatch arrête le suivi d'un conteneur. Sa position est gardée : s'il revient, la lecture reprend où elle en était.
func (f *LogForwarder) Unwatch(containerID string) {
	f.mu.Lock()
	if cancel, ok := f.watching[containerID]; ok {
		cancel()
		delete(f.watching, containerID)
	}
	f.mu.Unlock()
}

func (f *LogForwarder) cursor(containerID string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.cursors[containerID]
	return t, ok
}

// setCursor enregistre la position (en mémoire et sur le volume) une fois un lot acquitté.
func (f *LogForwarder) setCursor(containerID string, next time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cursors[containerID] = next
	if f.statePath == "" {
		return
	}
	data, err := json.Marshal(f.cursors)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f.statePath), 0o755); err != nil {
		f.log.Warn("logs: dossier des positions illisible", "err", err)
		return
	}
	tmp := f.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		f.log.Warn("logs: écriture des positions", "err", err)
		return
	}
	if err := os.Rename(tmp, f.statePath); err != nil {
		f.log.Warn("logs: remplacement du fichier des positions", "err", err)
	}
}

// stream suit un conteneur tant que ctx vit : chaque passe lit depuis la position enregistrée, et une passe qui
// s'arrête (flux terminé, passerelle injoignable) est reprise après une attente qui double jusqu'à retryMax.
func (f *LogForwarder) stream(ctx context.Context, containerID, containerName string) {
	wait := f.retryMin
	for ctx.Err() == nil {
		if f.followOnce(ctx, containerID, containerName) {
			wait = f.retryMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, f.retryMax)
	}
}

// followOnce lit les logs depuis la position enregistrée et les envoie par lots. Il retourne quand le flux se
// termine ou qu'un envoi échoue, et indique si au moins un lot a été acquitté. Les lignes lues mais non
// acquittées sont abandonnées : Docker les redonnera à la passe suivante.
func (f *LogForwarder) followOnce(ctx context.Context, containerID, containerName string) (progressed bool) {
	since, ok := f.cursor(containerID)
	if !ok {
		// Premier suivi : à partir de maintenant, l'historique d'avant l'Agent n'est pas rejoué.
		since = time.Now().UTC()
	}
	path := fmt.Sprintf("/containers/%s/logs?follow=1&stdout=1&stderr=1&timestamps=1&since=%d.%09d",
		containerID, since.Unix(), since.Nanosecond())

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lines := make(chan logEntry, 256)
	go func() {
		defer close(lines)
		_ = f.follow(cctx, path, func(line []byte) {
			// Les logs Docker sont préfixés par 8 octets de header (stream type + size)
			if len(line) > 8 {
				line = line[8:]
			}
			e := parseLogLine(line)
			// Bloquer plutôt que jeter : une ligne jetée serait ensuite dépassée par la position acquittée.
			select {
			case lines <- e:
			case <-cctx.Done():
			}
		})
	}()

	buf := make([]logEntry, 0, f.bufferLines)
	flush := func(sendCtx context.Context) bool {
		if len(buf) == 0 {
			return true
		}
		if err := f.send(sendCtx, containerID, containerName, buf); err != nil {
			f.log.Warn("logs: envoi vers la passerelle", "container", containerName, "lines", len(buf), "err", err)
			return false
		}
		f.setCursor(containerID, buf[len(buf)-1].T.Add(time.Nanosecond))
		buf = buf[:0]
		progressed = true
		return true
	}

	ticker := time.NewTicker(f.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Dernière tentative avec un contexte neuf : ce que la passerelle acquitte n'est pas relu au redémarrage.
			final, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			flush(final)
			return progressed
		case <-ticker.C:
			if !flush(ctx) {
				return progressed
			}
		case e, ok := <-lines:
			if !ok {
				flush(ctx)
				return progressed
			}
			buf = append(buf, e)
			if len(buf) >= f.bufferLines && !flush(ctx) {
				return progressed
			}
		}
	}
}

// parseLogLine sépare l'horodatage que Docker met en tête de ligne (timestamps=1) du message. Sans horodatage
// lisible, la ligne est gardée entière avec l'heure de lecture.
func parseLogLine(line []byte) logEntry {
	s := string(bytes.TrimRight(line, "\r\n"))
	if ts, rest, ok := strings.Cut(s, " "); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return logEntry{T: t.UTC(), Line: rest}
		}
	}
	return logEntry{T: time.Now().UTC(), Line: s}
}

type logEntry struct {
	T    time.Time `json:"t"`
	Line string    `json:"line"`
}

type logBatch struct {
	ContainerID   string     `json:"container_id"`
	ContainerName string     `json:"container_name"`
	Entries       []logEntry `json:"entries"`
}

// send remet un lot à la passerelle. Seule une réponse 2xx vaut accusé de réception.
func (f *LogForwarder) send(ctx context.Context, containerID, containerName string, entries []logEntry) error {
	batch := logBatch{
		ContainerID:   containerID,
		ContainerName: containerName,
		Entries:       entries,
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	url := f.adminEndpoint + "/internal/v1/agent/logs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("passerelle : %s", resp.Status)
	}
	f.log.Debug("logs: batch envoyé", "container", containerName, "lines", len(entries))
	return nil
}
