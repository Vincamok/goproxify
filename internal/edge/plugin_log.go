// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/plugins"
)

const (
	pluginLogQueueSize = 1024
	pluginLogWorkers   = 2
)

type pluginLogJob struct {
	p  *plugins.Plugin
	in plugins.LogInput
}

// pluginLogQueue exécute le hook « log » des plugins hors du chemin de la requête : la réponse est déjà partie
// quand le plugin est appelé, et un plugin lent ou en échec ne retarde personne. La file est bornée : quand elle
// est pleine, l'appel est abandonné et compté (gpx_plugin_log_dropped_total) plutôt que de retenir la mémoire.
type pluginLogQueue struct {
	once sync.Once
	ch   chan pluginLogJob
	done chan struct{}
}

func (q *pluginLogQueue) start(s *Server) {
	q.once.Do(func() {
		q.ch = make(chan pluginLogJob, pluginLogQueueSize)
		q.done = make(chan struct{})
		for range pluginLogWorkers {
			go func() {
				for {
					select {
					case <-q.done:
						return
					case job := <-q.ch:
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(job.p.Manifest.Limits.TimeoutMs)*time.Millisecond+time.Second)
						_, err := job.p.Call(ctx, plugins.HookLog, job.in)
						cancel()
						if err != nil {
							metrics.PluginLog.Calls.WithLabelValues(job.p.Manifest.Name, "error").Inc()
							s.log.Warn("plugin en échec", "plugin", job.p.Manifest.Name, "hook", "log", "err", err)
							continue
						}
						metrics.PluginLog.Calls.WithLabelValues(job.p.Manifest.Name, "ok").Inc()
					}
				}
			}()
		}
	})
}

func (q *pluginLogQueue) enqueue(s *Server, job pluginLogJob) {
	q.start(s)
	select {
	case q.ch <- job:
	default:
		metrics.PluginLog.Dropped.WithLabelValues(job.p.Manifest.Name).Inc()
	}
}

func (q *pluginLogQueue) stop() {
	if q.done == nil {
		return
	}
	select {
	case <-q.done:
	default:
		close(q.done)
	}
}

// logObserver note ce que le client reçoit (statut, octets) sans rien retenir ni modifier.
type logObserver struct {
	http.ResponseWriter
	status   int
	bytes    int64
	hijacked bool
}

func (o *logObserver) WriteHeader(code int) {
	if o.status == 0 {
		o.status = code
	}
	o.ResponseWriter.WriteHeader(code)
}

func (o *logObserver) Write(b []byte) (int, error) {
	if o.status == 0 {
		o.status = http.StatusOK
	}
	n, err := o.ResponseWriter.Write(b)
	o.bytes += int64(n)
	return n, err
}

func (o *logObserver) Unwrap() http.ResponseWriter { return o.ResponseWriter }

func (o *logObserver) Flush() {
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (o *logObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	o.hijacked = true
	return http.NewResponseController(o.ResponseWriter).Hijack()
}

// observe prépare l'enregistrement du hook log d'une requête : il retourne l'observateur à placer sur la
// réponse et la fonction à appeler une fois le handler terminé.
func (s *Server) observeForLog(w http.ResponseWriter, logHooks []activePlugin, in plugins.RequestInput) (*logObserver, func()) {
	obs := &logObserver{ResponseWriter: w}
	start := time.Now()
	return obs, func() {
		status := obs.status
		switch {
		case obs.hijacked:
			status = http.StatusSwitchingProtocols
		case status == 0:
			status = http.StatusOK
		}
		hdr := w.Header().Clone()
		for _, a := range logHooks {
			li := plugins.LogInput{
				ResponseInput: plugins.ResponseInput{RequestInput: in, Status: status, ResponseHeaders: hdr},
				DurationMs:    time.Since(start).Milliseconds(),
				BytesOut:      obs.bytes,
			}
			li.Config = a.cfg
			s.pluginLog.enqueue(s, pluginLogJob{p: a.p, in: li})
		}
	}
}
