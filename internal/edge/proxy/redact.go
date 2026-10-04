package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const redactMaxBody = 16 << 20

var errRedactUnsafe = errors.New("réponse JSON non masquable")

func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// applyRedactJSON masque les champs de cfg dans une réponse JSON. Elle échoue plutôt que de laisser
// passer une donnée à masquer : corps invalide, trop gros ou encodé autrement que gzip → erreur (502).
func applyRedactJSON(resp *http.Response, cfg *router.RedactConfig) error {
	if cfg == nil || len(cfg.Fields) == 0 || !isJSONContentType(resp.Header.Get("Content-Type")) || resp.Body == nil {
		return nil
	}
	var body io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "":
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errRedactUnsafe
		}
		defer gz.Close()
		body = gz
	default:
		return errRedactUnsafe
	}
	raw, err := io.ReadAll(io.LimitReader(body, redactMaxBody+1))
	resp.Body.Close()
	if err != nil || len(raw) > redactMaxBody {
		return errRedactUnsafe
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return errRedactUnsafe
		}
		mask := cfg.Mask
		if mask == "" {
			mask = "***"
		}
		redactValue(doc, "", cfg.Fields, mask)
		if raw, err = json.Marshal(doc); err != nil {
			return errRedactUnsafe
		}
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
	return nil
}

// redactValue remplace récursivement les valeurs dont la clé ou le chemin pointé figure dans fields.
func redactValue(v any, path string, fields []string, mask string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if fieldListed(fields, k, p) {
				t[k] = mask
				continue
			}
			redactValue(child, p, fields, mask)
		}
	case []any:
		for _, child := range t {
			redactValue(child, path, fields, mask)
		}
	}
}

func fieldListed(fields []string, key, path string) bool {
	for _, f := range fields {
		if strings.Contains(f, ".") {
			if f == path {
				return true
			}
		} else if strings.EqualFold(f, key) {
			return true
		}
	}
	return false
}
