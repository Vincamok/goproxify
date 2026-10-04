// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"os"
	"path/filepath"
)

// Fond de carte vectoriel auto-hébergé : un fichier PMTiles (données OpenStreetMap découpées par
// `pmtiles extract`) posé sur le serveur et servi tel quel. Le navigateur n'en lit que les tuiles
// visibles, par requêtes partielles (Range) : le fichier peut peser des Go sans être chargé en entier.
// Sans fichier, la carte garde ses contours de pays embarqués, plafonnés à un zoom régional.

const basemapRoute = "/map/basemap.pmtiles"

// basemapPath retourne l'emplacement du fond de carte : GPX_BASEMAP_PATH, sinon
// <stockage>/basemap/basemap.pmtiles. Vide si ni l'un ni l'autre n'est défini.
func basemapPath(basePath string) string {
	if p := os.Getenv("GPX_BASEMAP_PATH"); p != "" {
		return p
	}
	if basePath == "" {
		return ""
	}
	return filepath.Join(basePath, "basemap", "basemap.pmtiles")
}

// basemapHandler sert le fichier ; 404 tant qu'il n'existe pas (l'interface s'en sert pour savoir si
// le fond est disponible). Les données de la carte ne sont pas sensibles : la route est publique,
// comme l'interface qui les affiche.
func basemapHandler(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path == "" {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeContent(w, r, "basemap.pmtiles", st.ModTime(), f)
	})
}
