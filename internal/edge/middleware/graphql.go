package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const graphqlMaxBody = 1 << 20

// GraphQLLimits refuse (400) les requêtes GraphQL trop profondes, trop riches en alias,
// ou qui interrogent le schéma (introspection) quand c'est interdit.
func GraphQLLimits(cfg *router.GraphQLConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var queries []string
			switch {
			case r.Method == http.MethodGet && r.URL.Query().Get("query") != "":
				queries = []string{r.URL.Query().Get("query")}
			case r.Method == http.MethodPost && r.Body != nil:
				raw, err := io.ReadAll(io.LimitReader(r.Body, graphqlMaxBody+1))
				if err != nil || len(raw) > graphqlMaxBody {
					http.Error(w, "413 Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
				queries = extractGraphQLQueries(raw)
			}
			for _, q := range queries {
				if reason := checkGraphQL(q, cfg); reason != "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"errors":[{"message":"` + reason + `"}]}`))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractGraphQLQueries lit un corps {"query":…} ou un lot [{"query":…}, …] ;
// un corps application/graphql brut ou illisible est traité comme une requête.
func extractGraphQLQueries(raw []byte) []string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var batch []struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(trimmed, &batch) != nil {
			return []string{string(trimmed)}
		}
		out := make([]string, 0, len(batch))
		for _, b := range batch {
			out = append(out, b.Query)
		}
		return out
	case '{':
		var one struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(trimmed, &one) == nil {
			return []string{one.Query}
		}
	}
	return []string{string(trimmed)}
}

// checkGraphQL parcourt le texte sans l'analyser complètement : chaînes et commentaires sont
// ignorés, les accolades hors arguments donnent la profondeur, "nom:" hors arguments compte un alias.
func checkGraphQL(q string, cfg *router.GraphQLConfig) string {
	depth, maxDepth, parens, aliases := 0, 0, 0, 0
	var word strings.Builder
	prevWord := ""
	flush := func() {
		if word.Len() == 0 {
			return
		}
		prevWord = word.String()
		word.Reset()
		if cfg.BlockIntrospection && (prevWord == "__schema" || prevWord == "__type") {
			maxDepth = -1
		}
	}
	for i := 0; i < len(q) && maxDepth >= 0; i++ {
		c := q[i]
		switch {
		case c == '"':
			flush()
			if strings.HasPrefix(q[i:], `"""`) {
				end := strings.Index(q[i+3:], `"""`)
				if end < 0 {
					i = len(q)
				} else {
					i += 3 + end + 2
				}
				continue
			}
			for i++; i < len(q) && q[i] != '"'; i++ {
				if q[i] == '\\' {
					i++
				}
			}
		case c == '#':
			flush()
			for i < len(q) && q[i] != '\n' {
				i++
			}
		case c == '{':
			flush()
			if parens == 0 {
				depth++
				maxDepth = max(maxDepth, depth)
			}
		case c == '}':
			flush()
			if parens == 0 && depth > 0 {
				depth--
			}
		case c == '(':
			flush()
			parens++
		case c == ')':
			flush()
			if parens > 0 {
				parens--
			}
		case c == ':':
			flush()
			if parens == 0 && prevWord != "" {
				aliases++
			}
		case c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			word.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	switch {
	case maxDepth < 0:
		return "introspection interdite"
	case cfg.MaxDepth > 0 && maxDepth > cfg.MaxDepth:
		return "requête trop profonde"
	case cfg.MaxAliases > 0 && aliases > cfg.MaxAliases:
		return "trop d'alias"
	}
	return ""
}
