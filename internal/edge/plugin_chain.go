// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func pluginsDir() string {
	if p := os.Getenv("GPX_PLUGINS_DIR"); p != "" {
		return p
	}
	return "/etc/goproxify/plugins"
}

func (s *Server) ensurePluginManager() *plugins.Manager {
	if s.pluginMgr == nil {
		s.pluginMgr = plugins.NewManager(s.cache, pluginsDir(), s.log.Logger())
	}
	return s.pluginMgr
}

// loadPluginsFromDisk recharge les plugins installés, chiffrés sur la passerelle : ils fonctionnent sans
// l'Admin, y compris après un redémarrage (ADR 0006, ADR 0008).
func (s *Server) loadPluginsFromDisk(ctx context.Context) {
	n, errs := s.ensurePluginManager().LoadAll(ctx)
	for _, err := range errs {
		s.log.Warn("plugins: paquet ignoré", "err", err)
	}
	if n > 0 {
		s.log.Info("plugins: chargés depuis le disque", "count", n)
	}
}

// applyPlugins aligne les plugins sur la liste poussée par l'Admin.
func (s *Server) applyPlugins(pkgs []plugins.Package) {
	installed, removed, errs := s.ensurePluginManager().Sync(context.Background(), pkgs)
	for _, err := range errs {
		s.log.Warn("plugins: installation refusée", "err", err)
	}
	s.log.Info("plugins: synchronisés", "installed", installed, "removed", removed, "errors", len(errs))
}

type activePlugin struct {
	p   *plugins.Plugin
	cfg map[string]any
}

// pluginMiddleware exécute, dans l'ordre, les plugins attachés à la route. Un plugin référencé mais
// absent de la passerelle (pas encore poussé, retiré) refuse la requête (503) : la route ne devient
// jamais publique faute de plugin.
func (s *Server) pluginMiddleware(route *router.Route) func(http.Handler) http.Handler {
	refs := route.Plugins
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var active []activePlugin
			for _, ref := range refs {
				var p *plugins.Plugin
				if s.pluginMgr != nil {
					p, _ = s.pluginMgr.Get(ref.Name)
				}
				if p == nil {
					s.log.Error("plugin introuvable, accès refusé", "route", route.ID, "plugin", ref.Name)
					http.Error(w, "plugin indisponible", http.StatusServiceUnavailable)
					return
				}
				active = append(active, activePlugin{p: p, cfg: ref.Config})
			}

			in := plugins.RequestInput{
				Method: r.Method, Host: r.Host, Path: r.URL.Path, Query: r.URL.RawQuery,
				Headers: r.Header, ClientIP: edgelog.RealIP(r),
			}
			wantResp := false
			for _, a := range active {
				if a.p.Manifest.Has(plugins.HookResponse) {
					wantResp = true
				}
				if !a.p.Manifest.Has(plugins.HookRequest) {
					continue
				}
				in.Config = a.cfg
				out, err := a.p.Evaluate(r.Context(), plugins.HookRequest, in)
				if err != nil {
					s.log.Warn("plugin en échec", "route", route.ID, "plugin", a.p.Manifest.Name, "hook", "request", "err", err)
				}
				switch out.Action {
				case plugins.ActionDeny:
					writePluginDeny(w, out)
					return
				case plugins.ActionModify:
					applyHeaders(r.Header, out)
				}
			}
			if wantResp {
				w = &pluginResponseWriter{ResponseWriter: w, s: s, route: route, active: active, in: in}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writePluginDeny(w http.ResponseWriter, out plugins.Output) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(out.Status)
	_, _ = w.Write([]byte(out.Body))
}

func applyHeaders(h http.Header, out plugins.Output) {
	for _, k := range out.RemoveHeaders {
		h.Del(k)
	}
	for k, v := range out.SetHeaders {
		h.Set(k, v)
	}
}

// pluginResponseWriter laisse les plugins décider de la réponse au moment de l'envoi des en-têtes :
// modifier des en-têtes, ou remplacer la réponse par un refus (le corps du backend est alors écarté).
type pluginResponseWriter struct {
	http.ResponseWriter
	s       *Server
	route   *router.Route
	active  []activePlugin
	in      plugins.RequestInput
	wrote   bool
	discard bool
}

func (w *pluginResponseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	in := plugins.ResponseInput{RequestInput: w.in, Status: code, ResponseHeaders: w.Header()}
	for _, a := range w.active {
		if !a.p.Manifest.Has(plugins.HookResponse) {
			continue
		}
		in.Config = a.cfg
		out, err := a.p.Evaluate(context.Background(), plugins.HookResponse, in)
		if err != nil {
			w.s.log.Warn("plugin en échec", "route", w.route.ID, "plugin", a.p.Manifest.Name, "hook", "response", "err", err)
		}
		switch out.Action {
		case plugins.ActionDeny:
			w.discard = true
			writePluginDeny(w.ResponseWriter, out)
			return
		case plugins.ActionModify:
			applyHeaders(w.Header(), out)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *pluginResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.discard {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *pluginResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *pluginResponseWriter) Flush() {
	if w.discard {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *pluginResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
