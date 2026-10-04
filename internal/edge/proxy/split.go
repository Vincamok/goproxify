package proxy

import (
	"math/rand"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// pickSplit choisit la destination d'une requête parmi les variantes de route.Split.
// Ordre : forçage (header/cookie Override) → variante mémorisée (StickyCookie) → tirage pondéré.
// Retourne "" si aucune variante n'est utilisable (la requête suit alors le routage normal).
func (h *Handler) pickSplit(w http.ResponseWriter, r *http.Request) string {
	sp := h.route.Split
	var variants []router.SplitVariant
	total := 0
	for _, v := range sp.Variants {
		if v.Backend != "" && v.Weight > 0 {
			variants = append(variants, v)
			total += v.Weight
		}
	}
	if len(variants) == 0 {
		return ""
	}
	find := func(name string) *router.SplitVariant {
		for i := range sp.Variants {
			if sp.Variants[i].Name == name && sp.Variants[i].Backend != "" {
				return &sp.Variants[i]
			}
		}
		return nil
	}
	if sp.Override != "" {
		name := r.Header.Get(sp.Override)
		if name == "" {
			if c, err := r.Cookie(sp.Override); err == nil {
				name = c.Value
			}
		}
		if v := find(name); name != "" && v != nil {
			return v.Backend
		}
	}
	if sp.StickyCookie != "" {
		if c, err := r.Cookie(sp.StickyCookie); err == nil {
			if v := find(c.Value); v != nil {
				return v.Backend
			}
		}
	}
	n := rand.Intn(total)
	chosen := variants[len(variants)-1]
	for _, v := range variants {
		if n < v.Weight {
			chosen = v
			break
		}
		n -= v.Weight
	}
	if sp.StickyCookie != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     sp.StickyCookie,
			Value:    chosen.Name,
			Path:     "/",
			MaxAge:   30 * 24 * 3600,
			HttpOnly: true,
			Secure:   scheme(r) == "https",
			SameSite: http.SameSiteLaxMode,
		})
	}
	return chosen.Backend
}
