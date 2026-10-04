package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// SignURL calcule la signature attendue par SignedURL pour un chemin et une expiration (secondes Unix).
func SignURL(secret, path string, expires int64) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(path + "\n" + strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SignedURL refuse (403) toute requête dont la signature HMAC est absente, fausse ou expirée.
// La signature couvre le chemin (pas la query) : un lien reste valable pour sa ressource jusqu'à l'expiration.
// Les paramètres de signature sont retirés avant le backend.
func SignedURL(cfg *router.SignedURLConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled || cfg.Secret == "" {
			return next
		}
		pSig, pExp := cfg.ParamSig, cfg.ParamExpires
		if pSig == "" {
			pSig = "sig"
		}
		if pExp == "" {
			pExp = "expires"
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(cfg.Paths) > 0 && !pathHasPrefix(r.URL.Path, cfg.Paths) {
				next.ServeHTTP(w, r)
				return
			}
			q := r.URL.Query()
			sig := q.Get(pSig)
			expires, err := strconv.ParseInt(q.Get(pExp), 10, 64)
			if sig == "" || err != nil || time.Now().Unix() > expires ||
				!hmac.Equal([]byte(sig), []byte(SignURL(cfg.Secret, r.URL.Path, expires))) {
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			q.Del(pSig)
			q.Del(pExp)
			r.URL.RawQuery = q.Encode()
			next.ServeHTTP(w, r)
		})
	}
}

func pathHasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
