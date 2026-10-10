// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

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

// resolvePlugins retrouve les plugins d'une route. Un plugin référencé mais absent de la passerelle (pas
// encore poussé, retiré) renvoie false : la route refuse alors la requête (503) au lieu de devenir publique.
func (s *Server) resolvePlugins(route *router.Route) ([]activePlugin, string, bool) {
	active := make([]activePlugin, 0, len(route.Plugins))
	for _, ref := range route.Plugins {
		var p *plugins.Plugin
		if s.pluginMgr != nil {
			p, _ = s.pluginMgr.Get(ref.Name)
		}
		if p == nil {
			return nil, ref.Name, false
		}
		active = append(active, activePlugin{p: p, cfg: ref.Config})
	}
	return active, "", true
}

// pluginMiddleware exécute, dans l'ordre, les plugins attachés à la route : hook de requête, hook de corps de
// requête, puis (à l'envoi de la réponse) hooks de réponse et de corps de réponse.
func (s *Server) pluginMiddleware(route *router.Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active, missing, ok := s.resolvePlugins(route)
			if !ok {
				s.log.Error("plugin introuvable, accès refusé", "route", route.ID, "plugin", missing)
				http.Error(w, "plugin indisponible", http.StatusServiceUnavailable)
				return
			}

			in := plugins.RequestInput{
				Method: r.Method, Host: r.Host, Path: r.URL.Path, Query: r.URL.RawQuery,
				Headers: r.Header, ClientIP: edgelog.RealIP(r),
			}
			var respHooks, respBodyHooks []activePlugin
			for _, a := range active {
				if a.p.Manifest.Has(plugins.HookResponse) {
					respHooks = append(respHooks, a)
				}
				if a.p.Manifest.Has(plugins.HookResponseBody) {
					respBodyHooks = append(respBodyHooks, a)
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
					writePluginDeny(w, out, false)
					return
				case plugins.ActionModify:
					applyHeaders(r.Header, out)
				}
			}
			if !s.requestBodyHooks(w, r, route, active, in) {
				return
			}
			if len(respHooks) > 0 || len(respBodyHooks) > 0 {
				pw := newPluginResponseWriter(w, s, route, active, respBodyHooks, in)
				defer pw.finish()
				w = pw
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestBodyHooks passe le corps de la requête, tamponné, aux plugins qui déclarent request_body. Retourne
// false si la réponse a déjà été écrite (refus). Un corps plus gros que la limite d'un plugin suit sa
// politique on_oversize : refus (413) ou corps non examiné. Le flux d'origine est toujours restitué en
// entier au backend, sauf remplacement explicite par un plugin.
func (s *Server) requestBodyHooks(w http.ResponseWriter, r *http.Request, route *router.Route, active []activePlugin, in plugins.RequestInput) bool {
	var hooks []activePlugin
	maxLimit := 0
	for _, a := range active {
		if a.p.Manifest.Has(plugins.HookRequestBody) {
			hooks = append(hooks, a)
			maxLimit = max(maxLimit, a.p.Manifest.Limits.MaxBodyBytes)
		}
	}
	if len(hooks) == 0 || r.Body == nil || r.Body == http.NoBody {
		return true
	}
	orig := r.Body
	buf, err := io.ReadAll(io.LimitReader(orig, int64(maxLimit)+1))
	if err != nil {
		http.Error(w, "corps de requête illisible", http.StatusBadRequest)
		return false
	}
	// Plus que la plus grande limite : tous les plugins sont en dépassement (refus ou corps non examiné).
	exceeds := len(buf) > maxLimit
	body, replaced := buf, false
	for _, a := range hooks {
		if len(body) > a.p.Manifest.Limits.MaxBodyBytes {
			if a.p.Manifest.OnOversize == plugins.OnOversizeSkip {
				continue
			}
			http.Error(w, "corps trop volumineux pour le plugin "+a.p.Manifest.Name, http.StatusRequestEntityTooLarge)
			return false
		}
		bin := plugins.RequestBodyInput{RequestInput: in, Body: body}
		bin.Config = a.cfg
		out, err := a.p.Evaluate(r.Context(), plugins.HookRequestBody, bin)
		if err != nil {
			s.log.Warn("plugin en échec", "route", route.ID, "plugin", a.p.Manifest.Name, "hook", "request_body", "err", err)
		}
		switch out.Action {
		case plugins.ActionDeny:
			writePluginDeny(w, out, false)
			return false
		case plugins.ActionModify:
			applyHeaders(r.Header, out)
			if out.ReplaceBody != nil {
				body, replaced = *out.ReplaceBody, true
			}
		}
	}
	switch {
	case replaced:
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		r.Header.Del("Transfer-Encoding")
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	case exceeds:
		// Aucun plugin n'a pu examiner ce corps : le reste du flux n'a pas été lu, on le restitue.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), orig), orig}
	default:
		r.Body = io.NopCloser(bytes.NewReader(buf))
	}
	return true
}

// writePluginDeny écrit le refus d'un plugin. Pour un refus tardif (hook de réponse), les en-têtes propres à
// la réponse du backend sont retirés : un corps de refus en clair ne doit pas hériter de leur codage.
func writePluginDeny(w http.ResponseWriter, out plugins.Output, fromResponse bool) {
	h := w.Header()
	h.Del("Content-Length")
	if fromResponse {
		for _, k := range []string{"Content-Encoding", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Set-Cookie"} {
			h.Del(k)
		}
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
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

// pluginResponseWriter laisse les plugins décider de la réponse. Au moment de l'envoi des en-têtes, les hooks
// de réponse peuvent modifier des en-têtes ou remplacer la réponse par un refus. Si des plugins déclarent
// response_body, la réponse est retenue jusqu'à son terme (dans la limite de leurs tailles) pour que leurs
// hooks la voient en entier, puis envoyée.
type pluginResponseWriter struct {
	http.ResponseWriter
	s         *Server
	route     *router.Route
	active    []activePlugin
	bodyHooks []activePlugin
	maxBody   int
	in        plugins.RequestInput
	wrote     bool
	discard   bool // la réponse a été remplacée par un refus : le reste du corps est écarté
	buffering bool // en-têtes et corps retenus
	code      int
	buf       bytes.Buffer
	hijacked  bool
}

func newPluginResponseWriter(w http.ResponseWriter, s *Server, route *router.Route, active, bodyHooks []activePlugin, in plugins.RequestInput) *pluginResponseWriter {
	pw := &pluginResponseWriter{ResponseWriter: w, s: s, route: route, active: active, bodyHooks: bodyHooks, in: in}
	for _, a := range bodyHooks {
		pw.maxBody = max(pw.maxBody, a.p.Manifest.Limits.MaxBodyBytes)
	}
	return pw
}

func (w *pluginResponseWriter) denyResponse(out plugins.Output) {
	w.discard, w.buffering = true, false
	writePluginDeny(w.ResponseWriter, out, true)
}

// bufferable : la réponse a-t-elle un corps qu'on peut retenir ? Pas de corps (HEAD, 1xx, 204, 304) : rien à
// examiner. Un flux (text/event-stream) ne peut pas être retenu : il est traité comme un dépassement.
func (w *pluginResponseWriter) bodyless(code int) bool {
	return w.in.Method == http.MethodHead || code < 200 || code == http.StatusNoContent || code == http.StatusNotModified
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
			w.denyResponse(out)
			return
		case plugins.ActionModify:
			applyHeaders(w.Header(), out)
		}
	}
	if len(w.bodyHooks) == 0 || w.bodyless(code) {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.code, w.buffering = code, true
	// Réponse déjà annoncée plus grosse que toute limite, ou flux : inutile de retenir quoi que ce soit.
	if strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "text/event-stream") {
		w.overflow(nil)
		return
	}
	if cl, err := strconv.Atoi(w.Header().Get("Content-Length")); err == nil && cl > w.maxBody {
		w.overflow(nil)
	}
}

// overflow : la réponse dépasse la limite de tous les plugins de corps (ou ne peut pas être retenue). Un plugin
// en politique deny remplace la réponse par un refus (502) ; si tous sont en skip, la réponse est envoyée telle
// quelle, sans examen, et le reste est transmis au fil de l'eau.
func (w *pluginResponseWriter) overflow(pending []byte) {
	for _, a := range w.bodyHooks {
		if a.p.Manifest.OnOversize != plugins.OnOversizeSkip {
			w.denyResponse(plugins.Output{Status: http.StatusBadGateway, Body: "réponse trop volumineuse pour le plugin " + a.p.Manifest.Name})
			return
		}
	}
	w.buffering = false
	w.ResponseWriter.WriteHeader(w.code)
	if w.buf.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.buf.Bytes())
		w.buf.Reset()
	}
	if len(pending) > 0 {
		_, _ = w.ResponseWriter.Write(pending)
	}
}

func (w *pluginResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.discard {
		return len(b), nil
	}
	if w.buffering {
		if w.buf.Len()+len(b) > w.maxBody {
			w.overflow(b)
			return len(b), nil
		}
		return w.buf.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// finish envoie la réponse retenue après les hooks de corps. Appelé quand le handler suivant a terminé.
func (w *pluginResponseWriter) finish() {
	if w.hijacked || w.discard {
		return
	}
	if !w.wrote {
		w.WriteHeader(http.StatusOK) // une réponse vide est une réponse : les plugins la voient aussi
	}
	if !w.buffering || w.discard {
		return
	}
	w.buffering = false
	body := append([]byte(nil), w.buf.Bytes()...)
	in := plugins.ResponseBodyInput{ResponseInput: plugins.ResponseInput{RequestInput: w.in, Status: w.code, ResponseHeaders: w.Header()}}
	for _, a := range w.bodyHooks {
		if len(body) > a.p.Manifest.Limits.MaxBodyBytes {
			if a.p.Manifest.OnOversize == plugins.OnOversizeSkip {
				continue
			}
			w.denyResponse(plugins.Output{Status: http.StatusBadGateway, Body: "réponse trop volumineuse pour le plugin " + a.p.Manifest.Name})
			return
		}
		in.Body, in.Config = body, a.cfg
		out, err := a.p.Evaluate(context.Background(), plugins.HookResponseBody, in)
		if err != nil {
			w.s.log.Warn("plugin en échec", "route", w.route.ID, "plugin", a.p.Manifest.Name, "hook", "response_body", "err", err)
		}
		switch out.Action {
		case plugins.ActionDeny:
			w.denyResponse(out)
			return
		case plugins.ActionModify:
			applyHeaders(w.Header(), out)
			if out.ReplaceBody != nil {
				body = *out.ReplaceBody
			}
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.ResponseWriter.WriteHeader(w.code)
	if len(body) > 0 && w.in.Method != http.MethodHead {
		_, _ = w.ResponseWriter.Write(body)
	}
}

func (w *pluginResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *pluginResponseWriter) Flush() {
	if w.discard || w.buffering {
		return // une réponse retenue ne peut pas être vidée avant les hooks de corps
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *pluginResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
