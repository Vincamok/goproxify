// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net"
	"net/http"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

// loginSend envoie le code du second facteur (email, SMS, push) pendant la connexion. Jusqu'ici seuls les écrans du
// compte (une session complète) pouvaient en émettre : à la connexion, le champ de saisie attendait un code que rien
// n'avait envoyé, ces facteurs ne servaient donc qu'à l'activation.
//
// Le destinataire n'est jamais fourni par l'appelant : c'est l'adresse du compte ou le numéro / canal enregistré au
// moment de l'activation. Chaque envoi compte dans les mêmes limites que ceux de l'écran du compte.
func (h *MFAHandler) loginSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string     `json:"mfa_token"`
		Method   mfa.Method `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	userID, err := adminauth.VerifyMFAPendingToken(req.MFAToken, h.JWTSecret)
	if err != nil {
		http.Error(w, "token MFA invalide ou expiré", http.StatusUnauthorized)
		return
	}
	if blocked, wait := h.lim().blocked(userKey(userID)); blocked {
		tooManyMFAAttempts(w, wait)
		return
	}
	switch req.Method {
	case mfa.MethodEmail, mfa.MethodSMS, mfa.MethodPushNtfy, mfa.MethodPushGotify:
	default:
		http.Error(w, "cette méthode n'envoie pas de code", http.StatusBadRequest)
		return
	}
	if !h.methodVerified(r, userID, req.Method) {
		http.Error(w, "méthode non configurée", http.StatusBadRequest)
		return
	}
	if !h.allowSend(w, userID) {
		return
	}
	code, err := mfa.GenerateOTP(6)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.otp_gen")
		return
	}
	if _, err := h.Store.CreateChallenge(r.Context(), userID, req.Method, code, nil); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	var sendErr error
	switch req.Method {
	case mfa.MethodEmail:
		to := h.userEmail(r.Context(), userID)
		if to == "" {
			http.Error(w, "méthode non configurée", http.StatusBadRequest)
			return
		}
		sendErr = h.sendEmailOTP(to, code)
	case mfa.MethodSMS:
		cfg := h.smsCfg()
		var m struct {
			Phone string `json:"phone"`
		}
		if !cfg.Enabled || h.Store.GetMethodConfig(r.Context(), userID, mfa.MethodSMS, &m) != nil || !e164.MatchString(m.Phone) {
			http.Error(w, "méthode non configurée", http.StatusBadRequest)
			return
		}
		sendErr = mfa.SendSMS(r.Context(), cfg, m.Phone, "Goproxify — Code de connexion : "+code+" (valable 5 min)")
	default:
		var pc mfa.PushConfig
		if h.Store.GetMethodConfig(r.Context(), userID, req.Method, &pc) != nil {
			http.Error(w, "méthode non configurée", http.StatusBadRequest)
			return
		}
		ip, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			ip = r.RemoteAddr
		}
		sendErr = mfa.SendPushMFA(r.Context(), pc, code, r.UserAgent(), ip)
	}
	if sendErr != nil {
		h.Log.Error("mfa: envoi du code de connexion", "method", req.Method, "err", sendErr)
		http.Error(w, "envoi impossible", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// methodVerified : la méthode existe, est activée et a été vérifiée à l'activation.
func (h *MFAHandler) methodVerified(r *http.Request, userID string, method mfa.Method) bool {
	methods, err := h.Store.ListMethods(r.Context(), userID)
	if err != nil {
		return false
	}
	for _, m := range methods {
		if m.Method == method {
			return m.Enabled && m.Verified
		}
	}
	return false
}
