// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/vincamok/goproxify/internal/ssrf"
)

const (
	ocspRefreshEvery = time.Hour
	ocspFetchTimeout = 10 * time.Second
	ocspMaxResponse  = 1 << 20
)

// OCSPStatus décrit l'agrafe d'un certificat pour la métrique et les logs.
type OCSPStatus struct {
	NextUpdate time.Time
	Revoked    bool
}

// OCSPStapler agrafe aux certificats de la passerelle une réponse OCSP récupérée directement
// auprès de l'AC (extension AIA du certificat) : aucune dépendance à l'Admin, y compris après
// un redémarrage. Un certificat sans URL OCSP (Let's Encrypt, CA interne) est ignoré.
type OCSPStapler struct {
	store  *CertStore
	log    *slog.Logger
	client *http.Client
	// OnUpdate reçoit l'état des agrafes après chaque passe (métriques).
	OnUpdate func(map[string]OCSPStatus)
}

func NewOCSPStapler(store *CertStore, log *slog.Logger) *OCSPStapler {
	return &OCSPStapler{store: store, log: log, client: &http.Client{Timeout: ocspFetchTimeout}}
}

// Run rafraîchit les agrafes au démarrage, toutes les heures et à chaque nouveau certificat.
func (o *OCSPStapler) Run(ctx context.Context) {
	ticker := time.NewTicker(ocspRefreshEvery)
	defer ticker.Stop()
	for {
		o.RefreshAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-o.store.ocspKick:
			select { // laisse une rafale de push_cert se terminer
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}

// RefreshAll met à jour l'agrafe de chaque certificat dont la réponse manque ou approche de
// la moitié de sa validité. Une réponse est partagée entre les noms d'un même certificat.
func (o *OCSPStapler) RefreshAll(ctx context.Context) {
	fetched := map[string][]byte{}
	status := map[string]OCSPStatus{}
	for _, t := range o.store.ocspTargets() {
		leaf, issuer, err := leafAndIssuer(t.cert)
		if err != nil || len(leaf.OCSPServer) == 0 {
			continue
		}
		key := string(leaf.Raw)
		staple := t.cert.OCSPStaple
		if resp, ok := fetched[key]; ok {
			staple = resp
		} else if needsRefresh(staple, issuer) {
			resp, err := o.fetch(ctx, leaf, issuer)
			if err != nil {
				o.log.Warn("tls: OCSP indisponible", "cert", t.name, "err", err)
				if parsed, perr := ocsp.ParseResponseForCert(staple, leaf, issuer); perr != nil || !parsed.NextUpdate.After(time.Now()) {
					staple = nil // jamais d'agrafe périmée
				}
			} else {
				staple = resp
				o.log.Info("tls: OCSP agrafé", "cert", t.name)
			}
			fetched[key] = staple
		}
		if !bytes.Equal(staple, t.cert.OCSPStaple) {
			o.store.setStaple(t.name, t.cert, staple)
		}
		if parsed, err := ocsp.ParseResponseForCert(staple, leaf, issuer); err == nil {
			status[t.name] = OCSPStatus{NextUpdate: parsed.NextUpdate, Revoked: parsed.Status == ocsp.Revoked}
		}
	}
	if o.OnUpdate != nil {
		o.OnUpdate(status)
	}
}

func needsRefresh(staple []byte, issuer *x509.Certificate) bool {
	if len(staple) == 0 {
		return true
	}
	resp, err := ocsp.ParseResponse(staple, issuer)
	if err != nil {
		return true
	}
	half := resp.ThisUpdate.Add(resp.NextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().After(half)
}

func (o *OCSPStapler) fetch(ctx context.Context, leaf, issuer *x509.Certificate) ([]byte, error) {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, server := range leaf.OCSPServer {
		// L'URL vient du certificat (importable) : refuser les destinations internes.
		if err := ssrf.ValidateHTTPURL(server, ssrf.AllowPrivateEnv("GPX_OCSP_ALLOW_PRIVATE")); err != nil {
			lastErr = fmt.Errorf("%s : %w", server, err)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(reqDER))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		httpResp, err := o.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(httpResp.Body, ocspMaxResponse))
		httpResp.Body.Close()
		if err != nil || httpResp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s : statut %d", server, httpResp.StatusCode)
			continue
		}
		parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
		if err != nil {
			lastErr = fmt.Errorf("%s : %w", server, err)
			continue
		}
		if parsed.Status == ocsp.Unknown {
			lastErr = fmt.Errorf("%s : statut inconnu", server)
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("aucun serveur OCSP")
	}
	return nil, lastErr
}

func leafAndIssuer(c *tls.Certificate) (leaf, issuer *x509.Certificate, err error) {
	if len(c.Certificate) < 2 {
		return nil, nil, fmt.Errorf("chaîne sans émetteur")
	}
	if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return nil, nil, err
	}
	if issuer, err = x509.ParseCertificate(c.Certificate[1]); err != nil {
		return nil, nil, err
	}
	return leaf, issuer, nil
}

type ocspTarget struct {
	name string
	cert *tls.Certificate
}

func (s *CertStore) ocspTargets() []ocspTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ocspTarget, 0, len(s.certs))
	for n, c := range s.certs {
		out = append(out, ocspTarget{name: n, cert: c})
	}
	return out
}

// setStaple remplace le certificat par une copie agrafée, sauf s'il a été remplacé entre-temps.
func (s *CertStore) setStaple(name string, old *tls.Certificate, staple []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs[name] != old {
		return
	}
	c := *old
	c.OCSPStaple = staple
	s.certs[name] = &c
}

func (s *CertStore) kickOCSP() {
	select {
	case s.ocspKick <- struct{}{}:
	default:
	}
}
