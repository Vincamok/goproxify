// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package static sert un dossier de la passerelle, avec repli sur l'index pour les applications
// monopage (SPA).
package static

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const defaultIndex = "index.html"

// Handler sert les fichiers de cfg.Root. GET et HEAD seulement ; pas de liste de dossier, pas de
// fichiers cachés (segments commençant par un point). Un chemin introuvable retombe sur l'index
// si SPAFallback est actif et que la requête vise une page (pas d'extension, ou Accept: text/html) ;
// une ressource manquante (/app.js) reste un 404, sinon le navigateur recevrait du HTML à la place.
func Handler(cfg *router.StaticConfig) http.Handler {
	root := http.Dir(cfg.Root)
	index := cfg.Index
	if index == "" {
		index = defaultIndex
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if hasHiddenSegment(p) {
			http.NotFound(w, r)
			return
		}
		if serve(w, r, root, p, index, cfg) {
			return
		}
		if cfg.SPAFallback && wantsPage(r, p) && serve(w, r, root, "/"+index, index, cfg) {
			return
		}
		http.NotFound(w, r)
	})
}

func hasHiddenSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

func wantsPage(r *http.Request, p string) bool {
	if path.Ext(p) == "" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// serve écrit le fichier p (ou l'index du dossier p) ; retourne faux s'il n'existe pas.
func serve(w http.ResponseWriter, r *http.Request, root http.FileSystem, p, index string, cfg *router.StaticConfig) bool {
	f, err := root.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false
	}
	if st.IsDir() {
		f.Close()
		p = path.Join(p, index)
		if f, err = root.Open(p); err != nil {
			return false
		}
		defer f.Close()
		if st, err = f.Stat(); err != nil || st.IsDir() {
			return false
		}
	}
	h := w.Header()
	h.Set("ETag", fmt.Sprintf(`W/"%x-%x"`, st.Size(), st.ModTime().UnixNano()))
	if path.Base(p) == index {
		h.Set("Cache-Control", "no-cache")
	} else if cfg.CacheMaxAge > 0 {
		h.Set("Cache-Control", "public, max-age="+strconv.Itoa(cfg.CacheMaxAge))
	}
	http.ServeContent(w, r, path.Base(p), st.ModTime(), f)
	return true
}
