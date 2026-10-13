// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20

// newHTTPClient construit un client HTTP, avec une autorité de certification propre à l'annuaire si ca est fourni
// (certificat PEM ou chemin d'un fichier).
func newHTTPClient(ca string) (*http.Client, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second}
	if strings.TrimSpace(ca) != "" {
		pem := []byte(ca)
		if b, err := os.ReadFile(ca); err == nil {
			pem = b
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("certificat d'autorité illisible")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}, nil
}

// doJSON envoie une requête et décode la réponse JSON dans out (nil : réponse ignorée). Un statut hors 2xx est une
// erreur qui porte le début du corps.
func doJSON(ctx context.Context, c *http.Client, method, rawURL string, header map[string]string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return resp.StatusCode, fmt.Errorf("%s %s : HTTP %d %s", method, redactURL(rawURL), resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s : réponse illisible : %w", method, redactURL(rawURL), err)
		}
	}
	return resp.StatusCode, nil
}

// redactURL retire les identifiants et la requête d'une URL avant de la mettre dans un message d'erreur.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

// labelsFromTags range les étiquettes d'une liste « clé=valeur » (tags Consul et Nomad) dont la clé commence par prefix.
func labelsFromTags(tags []string, prefix string) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); strings.HasPrefix(k, prefix) {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

func hasEnableTag(tags []string, prefix string) bool {
	l := labelsFromTags(tags, prefix)
	return strings.EqualFold(l[prefix+"enable"], "true") || strings.EqualFold(l[prefix+"enabled"], "true")
}

// backendURL compose l'URL d'une instance ; les étiquettes « scheme » et « port » du service la complètent.
func backendURL(labels map[string]string, prefix, addr string, port int) string {
	if addr == "" {
		return ""
	}
	scheme := strings.ToLower(labels[prefix+"scheme"])
	if scheme != "https" {
		scheme = "http"
	}
	if p, err := strconv.Atoi(labels[prefix+"port"]); err == nil && p > 0 && p < 65536 {
		port = p
	}
	if port <= 0 || port > 65535 {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(addr, strconv.Itoa(port))
}

func shortAddr(backend string) string {
	return strings.TrimPrefix(strings.TrimPrefix(backend, "http://"), "https://")
}
