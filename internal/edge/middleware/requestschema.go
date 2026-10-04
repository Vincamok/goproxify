// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	requestSchemaDefaultMaxBody = 1 << 20
	requestSchemaMaxDetails     = 5
)

// noLoader interdit tout chargement externe ($ref vers une URL ou un fichier) : un schéma doit
// être autonome, sinon la passerelle ferait des requêtes sortantes pour le compte d'un schéma.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("référence externe interdite : %s", url)
}

type compiledSchemaRule struct {
	methods map[string]bool
	prefix  string
	schema  *jsonschema.Schema
}

func compileSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	if err := c.AddResource("gpx://request-schema", doc); err != nil {
		return nil, err
	}
	return c.Compile("gpx://request-schema")
}

func compileRequestSchemas(cfg *router.RequestSchemaConfig) ([]compiledSchemaRule, error) {
	var out []compiledSchemaRule
	for i, r := range cfg.Rules {
		s, err := compileSchema(r.Schema)
		if err != nil {
			return nil, fmt.Errorf("request_schema.rules[%d].schema: %w", i, err)
		}
		methods := map[string]bool{}
		for _, m := range r.Methods {
			methods[strings.ToUpper(m)] = true
		}
		if len(methods) == 0 {
			methods = map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true}
		}
		out = append(out, compiledSchemaRule{methods: methods, prefix: r.PathPrefix, schema: s})
	}
	return out, nil
}

// ValidateRequestSchemaConfig retourne les erreurs de configuration (utilisé par le dry-run).
func ValidateRequestSchemaConfig(cfg *router.RequestSchemaConfig) []string {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	var errs []string
	if cfg.Mode != "" && cfg.Mode != "block" && cfg.Mode != "detect" {
		errs = append(errs, `request_schema.mode invalide (block ou detect)`)
	}
	if cfg.MaxBody < 0 {
		errs = append(errs, "request_schema.max_body doit être positif")
	}
	if len(cfg.Rules) == 0 {
		errs = append(errs, "request_schema.rules : au moins une règle requise")
	}
	if _, err := compileRequestSchemas(cfg); err != nil {
		errs = append(errs, err.Error())
	}
	return errs
}

func isJSONContent(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// RequestSchema valide le corps JSON des requêtes contre un JSON Schema (première règle dont la
// méthode et le préfixe de chemin correspondent). Mode block (défaut) : 422 si invalide, 413 si le
// corps dépasse max_body. Mode detect : la requête passe toujours, seule la métrique compte.
// Les corps non JSON ne sont pas validés. Une configuration invalide laisse tout passer (le
// dry-run la refuse à l'enregistrement).
func RequestSchema(host string, cfg *router.RequestSchemaConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		rules, err := compileRequestSchemas(cfg)
		if err != nil || len(rules) == 0 {
			return next
		}
		block := cfg.Mode != "detect"
		maxBody := cfg.MaxBody
		if maxBody <= 0 {
			maxBody = requestSchemaDefaultMaxBody
		}
		count := func(result string) { metrics.Routing.RequestSchema.WithLabelValues(host, result).Inc() }
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rule *compiledSchemaRule
			for i := range rules {
				if rules[i].methods[r.Method] && strings.HasPrefix(r.URL.Path, rules[i].prefix) {
					rule = &rules[i]
					break
				}
			}
			if rule == nil || !isJSONContent(r.Header.Get("Content-Type")) || r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil {
				http.Error(w, "400 Bad Request", http.StatusBadRequest)
				return
			}
			if int64(len(raw)) > maxBody {
				count("skipped")
				if block {
					http.Error(w, "413 Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				r.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(raw), r.Body), r.Body}
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			if details := validateAgainst(rule.schema, raw); len(details) > 0 {
				count("invalid")
				if block {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error":   "request body does not match the schema",
						"details": details,
					})
					return
				}
			} else {
				count("valid")
			}
			next.ServeHTTP(w, r)
		})
	}
}

type schemaDetail struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// validateAgainst retourne les écarts (au plus requestSchemaMaxDetails), nil si le corps est valide.
func validateAgainst(s *jsonschema.Schema, raw []byte) []schemaDetail {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []schemaDetail{{Path: "", Message: "corps vide"}}
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return []schemaDetail{{Path: "", Message: "JSON invalide"}}
	}
	err = s.Validate(doc)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []schemaDetail{{Message: "validation impossible"}}
	}
	var out []schemaDetail
	var walk func(u jsonschema.OutputUnit)
	walk = func(u jsonschema.OutputUnit) {
		if len(out) >= requestSchemaMaxDetails {
			return
		}
		if u.Error != nil {
			out = append(out, schemaDetail{Path: u.InstanceLocation, Message: u.Error.String()})
		}
		for _, c := range u.Errors {
			walk(c)
		}
	}
	walk(*ve.BasicOutput())
	if len(out) == 0 {
		out = []schemaDetail{{Message: "corps non conforme"}}
	}
	return out
}
