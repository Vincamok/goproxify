// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestGeoJSONServedGzipped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/lib/world/regions.geojson", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("réponse non compressée : %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	var fc struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.NewDecoder(zr).Decode(&fc); err != nil || len(fc.Features) < 3000 {
		t.Fatalf("GeoJSON invalide ou incomplet : %v (%d entités)", err, len(fc.Features))
	}

	plain := httptest.NewRecorder()
	Handler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/lib/world/countries.geojson", nil))
	if plain.Header().Get("Content-Encoding") != "" || plain.Code != http.StatusOK {
		t.Fatalf("sans Accept-Encoding, la réponse doit rester brute : %d %v", plain.Code, plain.Header())
	}
}

func readSrc(t *testing.T, name string) string {
	t.Helper()
	b, err := srcFS.ReadFile("src/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// themeBlock extrait le corps du bloc CSS ouvert par selector (premier « } » en début de ligne).
func themeBlock(t *testing.T, css, selector string) string {
	t.Helper()
	i := strings.Index(css, "\n"+selector+" {\n")
	if i < 0 {
		t.Fatalf("bloc %q introuvable", selector)
	}
	body := css[i+len(selector)+4:]
	return body[:strings.Index(body, "\n}")]
}

func cssVars(block string) map[string]string {
	vars := map[string]string{}
	for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):\s*([^;]+);`).FindAllStringSubmatch(block, -1) {
		vars[m[1]] = strings.TrimSpace(m[2])
	}
	return vars
}

func luminance(hex string) float64 {
	var c [3]float64
	for i := range c {
		v, _ := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		f := float64(v) / 255
		if f <= 0.03928 {
			c[i] = f / 12.92
		} else {
			c[i] = math.Pow((f+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

func contrast(a, b string) float64 {
	x, y := luminance(a), luminance(b)
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// Chaque skin déclaré dans app.config.js a sa feuille de variables, embarquée et branchée dans index.html ;
// le skin par défaut reste « flat ».
func TestSkinsAreDeclaredAndEmbedded(t *testing.T) {
	cfg, html := readSrc(t, "app.config.js"), readSrc(t, "index.html")
	if !strings.Contains(cfg, "skin: 'flat',") {
		t.Error("le skin par défaut doit rester « flat »")
	}
	ids := regexp.MustCompile(`\bid: '([a-z-]+)',\n\s+label:`).FindAllStringSubmatch(cfg, -1)
	if len(ids) < 3 {
		t.Fatalf("skins déclarés : %d, attendu au moins flat, industry-ds et console", len(ids))
	}
	for _, m := range ids {
		id := m[1]
		if !strings.Contains(html, `data-skin="`+id+`" media="not all" href="themes/`+id+`.css"`) {
			t.Errorf("index.html : feuille du skin %q non branchée", id)
		}
		if _, err := srcFS.ReadFile("src/themes/" + id + ".css"); err != nil {
			t.Errorf("skin %q : %v", id, err)
		}
	}
	if !strings.Contains(cfg, "label: 'Console'") {
		t.Error("skin Console absent du catalogue")
	}
}

// L'Admin ne fait aucune requête externe tant qu'un skin n'en déclare pas : polices chargées à l'activation du skin seulement.
var externalRef = regexp.MustCompile(`url\(\s*["']?https?:|https://`)

func TestAdminPageLoadsNoExternalFont(t *testing.T) {
	if html := readSrc(t, "index.html"); strings.Contains(html, "fonts.googleapis.com") || strings.Contains(html, "fonts.gstatic.com") {
		t.Error("index.html ne doit référencer aucune police externe")
	}
	for _, f := range []string{"app.config.js", "themes/flat.css", "themes/industry-ds.css", "themes/console.css"} {
		src := readSrc(t, f)
		if f == "app.config.js" {
			src = src[strings.Index(src, "id: 'console'"):]
			src = src[:strings.Index(src, "\n    },")]
		}
		if externalRef.MatchString(src) || strings.Contains(src, "@import") {
			t.Errorf("%s : aucune URL ni @import externe attendu", f)
		}
	}
}

func TestConsoleSkinTokens(t *testing.T) {
	css := readSrc(t, "themes/console.css")
	required := []string{"--bg", "--bg2", "--bg3", "--border", "--text", "--text2", "--text3", "--accent", "--accent-hover",
		"--green", "--red", "--yellow", "--blue", "--cyan", "--purple", "--radius", "--radius-lg", "--shadow", "--shadow-lg",
		"--sidebar-w", "--font", "--font-heading", "--color-accent", "--color-accent-100", "--color-surface", "--color-divider"}
	light, dark := cssVars(themeBlock(t, css, ":root")), cssVars(themeBlock(t, css, `[data-theme="dark"]`))
	for _, v := range required {
		if light[v] == "" {
			t.Errorf("variable %s absente du thème clair", v)
		}
		if dark[v] == "" && light[v] != "" && !strings.HasPrefix(light[v], "var(") && !strings.HasPrefix(light[v], "color-mix") &&
			v != "--radius" && v != "--radius-lg" && v != "--sidebar-w" && v != "--font" && v != "--font-heading" {
			t.Errorf("variable %s absente du thème sombre", v)
		}
	}
	for _, f := range []string{"flat.css", "industry-ds.css"} {
		if _, err := srcFS.ReadFile("src/themes/" + f); err != nil {
			t.Error(err)
		}
	}
}

// Texte et couleurs sémantiques lisibles (WCAG AA, 4,5:1) sur les trois surfaces, en clair comme en sombre ;
// chaque accent l'est aussi, avec sa variante sombre.
func TestConsoleSkinContrast(t *testing.T) {
	css := readSrc(t, "themes/console.css")
	for name, block := range map[string]string{"clair": themeBlock(t, css, ":root"), "sombre": themeBlock(t, css, `[data-theme="dark"]`)} {
		v := cssVars(block)
		for _, fg := range []string{"--text", "--text2", "--text3", "--accent", "--green", "--red", "--yellow", "--blue", "--cyan", "--purple", "--orange"} {
			for _, bg := range []string{"--bg", "--bg2", "--bg3"} {
				if c := contrast(v[fg], v[bg]); c < 4.5 {
					t.Errorf("thème %s : %s sur %s = %.2f:1 (< 4,5)", name, fg, bg, c)
				}
			}
		}
		if v["--green"] == v["--accent"] {
			t.Errorf("thème %s : le vert de statut doit se distinguer de l'accent", name)
		}
	}
	light, dark := cssVars(themeBlock(t, css, ":root")), cssVars(themeBlock(t, css, `[data-theme="dark"]`))
	cfg := readSrc(t, "app.config.js")
	cfg = cfg[strings.Index(cfg, "id: 'console'"):]
	cfg = cfg[:strings.Index(cfg, "\n    },")]
	accents := regexp.MustCompile(`color: '(#[0-9a-f]{6})', hover: '(#[0-9a-f]{6})', dark: \{ color: '(#[0-9a-f]{6})', hover: '(#[0-9a-f]{6})' \}`).FindAllStringSubmatch(cfg, -1)
	if len(accents) != 4 {
		t.Fatalf("accents Console : %d, attendu 4 avec variante sombre", len(accents))
	}
	for _, a := range accents {
		for _, bg := range []string{"--bg", "--bg2", "--bg3"} {
			if c := contrast(a[1], light[bg]); c < 4.5 {
				t.Errorf("accent %s sur %s clair = %.2f:1", a[1], bg, c)
			}
			if c := contrast(a[3], dark[bg]); c < 4.5 {
				t.Errorf("accent sombre %s sur %s sombre = %.2f:1", a[3], bg, c)
			}
		}
		if c := contrast(a[2], light["--on-accent"]); c < 4.5 {
			t.Errorf("survol %s : texte blanc = %.2f:1", a[2], c)
		}
		if c := contrast(a[3], dark["--on-accent"]); c < 4.5 {
			t.Errorf("accent sombre %s : texte sombre = %.2f:1", a[3], c)
		}
	}
}
