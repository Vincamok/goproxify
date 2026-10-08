// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // imposé par le schéma de signature de l'API OVH ($1$)
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// --- OVH -------------------------------------------------------------------

const ovhDefaultEndpoint = "https://eu.api.ovh.com/1.0"

// ovhEndpoints traduit les noms courts d'endpoint (ceux de la documentation OVH et de l'assistant
// d'installation) en URL d'API.
var ovhEndpoints = map[string]string{
	"ovh-eu": "https://eu.api.ovh.com/1.0",
	"ovh-ca": "https://ca.api.ovh.com/1.0",
	"ovh-us": "https://api.us.ovhcloud.com/1.0",
}

type ovhProvider struct {
	endpoint    string
	appKey      string
	appSecret   string
	consumerKey string
	zone        string

	// Valeurs nulles par défaut ; les tests injectent les leurs.
	client     *http.Client
	now        func() time.Time
	timeDelta  int64 // décalage horloge OVH − horloge locale, en secondes
	timeSynced bool
}

func newOVHProvider(p map[string]string) (DNSProvider, error) {
	ep := p["endpoint"]
	if full, ok := ovhEndpoints[strings.ToLower(ep)]; ok {
		ep = full
	}
	if ep == "" {
		ep = ovhDefaultEndpoint
	}
	return &ovhProvider{
		endpoint:    strings.TrimRight(ep, "/"),
		appKey:      p["app_key"],
		appSecret:   p["app_secret"],
		consumerKey: p["consumer_key"],
		zone:        p["zone"],
	}, nil
}

// SetTXTRecord ajoute un TXT de challenge puis rafraîchit la zone : sans ce rafraîchissement OVH
// ne publie pas l'enregistrement. Les TXT déjà présents (wildcard + apex) sont conservés.
func (o *ovhProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	err := o.call(ctx, http.MethodPost, "/domain/zone/"+o.zone+"/record", map[string]any{
		"fieldType": "TXT",
		"subDomain": challengeLabel(domain, o.zone),
		"target":    value,
		"ttl":       60,
	}, nil)
	if err != nil {
		return err
	}
	return o.refresh(ctx)
}

// DeleteTXTRecord supprime les TXT de challenge du nom, retrouvés par leur identifiant. Rien à
// supprimer n'est pas une erreur.
func (o *ovhProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	sub := challengeLabel(domain, o.zone)
	var ids []int64
	q := "?fieldType=TXT&subDomain=" + url.QueryEscape(sub)
	if err := o.call(ctx, http.MethodGet, "/domain/zone/"+o.zone+"/record"+q, nil, &ids); err != nil {
		return err
	}
	for _, id := range ids {
		if err := o.call(ctx, http.MethodDelete, "/domain/zone/"+o.zone+"/record/"+strconv.FormatInt(id, 10), nil, nil); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return o.refresh(ctx)
}

func (o *ovhProvider) refresh(ctx context.Context) error {
	return o.call(ctx, http.MethodPost, "/domain/zone/"+o.zone+"/refresh", nil, nil)
}

// timestamp retourne l'heure d'OVH : l'API refuse une signature dont l'horodatage s'écarte
// trop de la sienne. Le décalage est lu une fois (GET /auth/time, non signé) ; sans réponse, on
// garde l'horloge locale.
func (o *ovhProvider) timestamp(ctx context.Context) int64 {
	now := time.Now
	if o.now != nil {
		now = o.now
	}
	if !o.timeSynced {
		o.timeSynced = true
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.endpoint+"/auth/time", nil); err == nil {
			if resp, err := httpClient(o.client).Do(req); err == nil {
				var t int64
				if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&t) == nil && t > 0 {
					o.timeDelta = t - now().Unix()
				}
				resp.Body.Close()
			}
		}
	}
	return now().Unix() + o.timeDelta
}

// ovhSignature calcule l'en-tête X-Ovh-Signature : "$1$" + SHA1 de
// secret+consumerKey+méthode+URL+corps+horodatage, séparés par « + ».
func ovhSignature(appSecret, consumerKey, method, fullURL, body string, ts int64) string {
	h := sha1.Sum([]byte(strings.Join([]string{appSecret, consumerKey, method, fullURL, body, strconv.FormatInt(ts, 10)}, "+"))) //nolint:gosec
	return "$1$" + hex.EncodeToString(h[:])
}

// call exécute une requête signée. body (optionnel) est sérialisé en JSON ; out (optionnel)
// reçoit la réponse décodée.
func (o *ovhProvider) call(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	fullURL := o.endpoint + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	ts := o.timestamp(ctx)
	req.Header.Set("X-Ovh-Application", o.appKey)
	req.Header.Set("X-Ovh-Consumer", o.consumerKey)
	req.Header.Set("X-Ovh-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Ovh-Signature", ovhSignature(o.appSecret, o.consumerKey, method, fullURL, string(payload), ts))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient(o.client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ovh: HTTP %d: %s", resp.StatusCode, bodyText(resp.Body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
