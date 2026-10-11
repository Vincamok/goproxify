// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	PATPrefix          = "gpx_pat_"
	AuthKindJWT        = "jwt"
	AuthKindPAT        = "pat"
	ctxAuthKind        contextKey = "authKind"
	ctxPATID           contextKey = "patID"
	ctxPATScopes       contextKey = "patScopes"
)

// GeneratePAT produit un token utilisateur au format gpx_pat_<32-hex>.
func GeneratePAT() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: génération PAT : %v", err))
	}
	return PATPrefix + hex.EncodeToString(b)
}

// HashPAT retourne le hash SHA-256 hexadécimal du secret en clair.
func HashPAT(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// PATPreview retourne un aperçu sûr pour l'UI (préfixe + 4 derniers caractères).
func PATPreview(plain string) string {
	if len(plain) < 12 {
		return PATPrefix + "…"
	}
	return plain[:len(PATPrefix)+4] + "…" + plain[len(plain)-4:]
}

// IsPATToken indique si la chaîne ressemble à un PAT utilisateur.
func IsPATToken(token string) bool {
	return strings.HasPrefix(token, PATPrefix)
}

// LookupPAT résout un PAT valide (non révoqué, non expiré) et retourne userID, tokenID, scopes.
func LookupPAT(ctx context.Context, db *sql.DB, plain string) (userID, tokenID string, scopes []string, err error) {
	if !IsPATToken(plain) {
		return "", "", nil, errors.New("pas un PAT")
	}
	hash := HashPAT(plain)
	var expires sql.NullTime
	var revoked int
	// La jointure sur users : le jeton d'un compte supprimé ne doit plus ouvrir aucune porte (rien ne le révoquait).
	err = db.QueryRowContext(ctx, `
		SELECT t.id, t.user_id, t.revoked, t.expires_at
		FROM user_api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ?`, hash).Scan(&tokenID, &userID, &revoked, &expires)
	if err != nil {
		return "", "", nil, fmt.Errorf("PAT inconnu")
	}
	if revoked != 0 {
		return "", "", nil, errors.New("PAT révoqué")
	}
	if expires.Valid && !expires.Time.After(time.Now().UTC()) {
		return "", "", nil, errors.New("PAT expiré")
	}
	rows, err := db.QueryContext(ctx,
		`SELECT scope FROM user_api_token_scopes WHERE token_id = ? ORDER BY scope`, tokenID)
	if err != nil {
		return "", "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", "", nil, err
		}
		scopes = append(scopes, s)
	}
	if err := rows.Err(); err != nil {
		return "", "", nil, err
	}
	if scopes == nil {
		scopes = []string{}
	}
	// last_used_at best-effort
	_, _ = db.ExecContext(ctx,
		`UPDATE user_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, tokenID)
	return userID, tokenID, scopes, nil
}

// RequireAuth accepte un JWT de session UI ou un PAT utilisateur.
func RequireAuth(secret string, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Authorization manquant", http.StatusUnauthorized)
				return
			}
			ctx, err := authenticateBearer(r.Context(), secret, db, tokenStr)
			if err != nil {
				http.Error(w, "Token invalide", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePAT n'accepte que les tokens utilisateur (gpx_pat_*) — utilisé pour le MCP.
func RequirePAT(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Authorization manquant", http.StatusUnauthorized)
				return
			}
			if !IsPATToken(tokenStr) {
				http.Error(w, "MCP : un token API utilisateur (gpx_pat_*) est requis", http.StatusUnauthorized)
				return
			}
			userID, patID, scopes, err := LookupPAT(r.Context(), db, tokenStr)
			if err != nil {
				http.Error(w, "Token invalide", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUserID, userID)
			ctx = context.WithValue(ctx, ctxAuthKind, AuthKindPAT)
			ctx = context.WithValue(ctx, ctxPATID, patID)
			ctx = context.WithValue(ctx, ctxPATScopes, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authenticateBearer(ctx context.Context, secret string, db *sql.DB, tokenStr string) (context.Context, error) {
	if IsPATToken(tokenStr) {
		userID, patID, scopes, err := LookupPAT(ctx, db, tokenStr)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, ctxUserID, userID)
		ctx = context.WithValue(ctx, ctxAuthKind, AuthKindPAT)
		ctx = context.WithValue(ctx, ctxPATID, patID)
		ctx = context.WithValue(ctx, ctxPATScopes, scopes)
		return ctx, nil
	}
	userID, issued, err := VerifyJWTIssued(tokenStr, secret)
	if err != nil {
		return nil, err
	}
	// Un JWT vaut 24 h : sans cette vérification, un compte supprimé gardait sa session jusqu'à l'échéance, et une
	// session volée survivait à un changement de mot de passe.
	var validAfter int64
	if err := db.QueryRowContext(ctx, `SELECT tokens_valid_after FROM users WHERE id = ?`, userID).Scan(&validAfter); err != nil {
		return nil, errors.New("utilisateur inconnu")
	}
	if issued.Unix() < validAfter {
		return nil, errors.New("session révoquée")
	}
	ctx = context.WithValue(ctx, ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxAuthKind, AuthKindJWT)
	return ctx, nil
}

// AuthKindFromContext retourne "jwt", "pat" ou "".
func AuthKindFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxAuthKind).(string)
	return v
}

// IsPATAuth indique si la requête est authentifiée via PAT.
func IsPATAuth(ctx context.Context) bool {
	return AuthKindFromContext(ctx) == AuthKindPAT
}

// PATIDFromContext retourne l'ID du PAT courant (vide si JWT).
func PATIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxPATID).(string)
	return v
}

// PATScopesFromContext retourne les scopes déclarés sur le PAT (nil si JWT).
func PATScopesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(ctxPATScopes).([]string)
	return v
}

// ActorFromContext formate l'acteur d'audit (indique un PAT le cas échéant).
func ActorFromContext(ctx context.Context) string {
	uid := UserIDFromContext(ctx)
	if IsPATAuth(ctx) {
		return uid + " via pat:" + PATIDFromContext(ctx)
	}
	return uid
}

// RevokeSessions révoque les sessions (JWT) déjà émises pour l'utilisateur : celles dont la date d'émission précède
// maintenant sont refusées. Appelée à chaque changement de mot de passe. Les jetons API (PAT) ne sont pas touchés :
// ils se révoquent un par un.
func RevokeSessions(ctx context.Context, db *sql.DB, userID string) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET tokens_valid_after = ? WHERE id = ?`, time.Now().Unix(), userID)
	return err
}
