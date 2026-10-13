// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	htmlInjectMaxBody    = 8 << 20
	htmlInjectMaxContent = 16 << 10
)

// applyHTMLInject insère cfg.Content dans une page HTML : avant le premier </head> (head_end) ou avant le
// dernier </body> (body_end, le dernier parce qu'un script de la page peut contenir la chaîne). Une réponse qui
// n'est pas du HTML, qui est encodée autrement que gzip, qui dépasse 8 Mio ou sans ancre est laissée intacte :
// une injection manquée ne casse pas la page.
func applyHTMLInject(resp *http.Response, cfg *router.HTMLInjectConfig) error {
	if cfg == nil || cfg.Content == "" || len(cfg.Content) > htmlInjectMaxContent || resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "text/html" {
		return nil
	}
	enc := resp.Header.Get("Content-Encoding")
	if enc != "" && enc != "gzip" {
		return nil
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, htmlInjectMaxBody+1))
	if err != nil || len(raw) > htmlInjectMaxBody {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	keep := func() {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
	}
	page := raw
	if enc == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			keep()
			return nil
		}
		page, err = io.ReadAll(io.LimitReader(gz, htmlInjectMaxBody+1))
		if err != nil || len(page) > htmlInjectMaxBody {
			keep()
			return nil
		}
	}

	at := -1
	if cfg.Position == router.HTMLInjectHeadEnd {
		at = indexFoldASCII(page, "</head>", false)
	} else {
		at = indexFoldASCII(page, "</body>", true)
	}
	if at < 0 {
		keep()
		return nil
	}

	content := cfg.Content
	if cfg.CSPNonce && strings.Contains(content, "{{nonce}}") {
		nonce := newNonce()
		content = strings.ReplaceAll(content, "{{nonce}}", nonce)
		addNonceToCSP(resp.Header, nonce)
	}
	out := make([]byte, 0, len(page)+len(content))
	out = append(out, page[:at]...)
	out = append(out, content...)
	out = append(out, page[at:]...)

	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

// indexFoldASCII cherche needle (en minuscules ASCII) sans tenir compte de la casse, sans copier ni changer la
// longueur du texte (bytes.ToLower peut en changer pour certains caractères non ASCII). last : dernière occurrence.
func indexFoldASCII(s []byte, needle string, last bool) int {
	found := -1
	for i := 0; i+len(needle) <= len(s); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			if !last {
				return i
			}
			found = i
		}
	}
	return found
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

// addNonceToCSP ajoute le nonce à script-src de chaque Content-Security-Policy de la réponse (à default-src à
// défaut), pour que le script injecté ne soit pas bloqué par la politique du backend.
func addNonceToCSP(h http.Header, nonce string) {
	vals := h.Values("Content-Security-Policy")
	if len(vals) == 0 {
		return
	}
	token := "'nonce-" + nonce + "'"
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = addNonceToPolicy(v, token)
	}
	h["Content-Security-Policy"] = out
}

func addNonceToPolicy(policy, token string) string {
	dirs := strings.Split(policy, ";")
	target := -1
	for i, d := range dirs {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "script-src":
			target = i
		case "default-src":
			if target < 0 {
				target = i
			}
		}
		if strings.EqualFold(f[0], "script-src") {
			break
		}
	}
	if target < 0 {
		return policy
	}
	dirs[target] = strings.TrimRight(dirs[target], " ") + " " + token
	return strings.Join(dirs, ";")
}
