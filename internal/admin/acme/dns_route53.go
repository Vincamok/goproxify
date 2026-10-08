// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// --- Route 53 --------------------------------------------------------------
//
// Appels HTTP directs à l'API Route 53 signés en AWS Signature Version 4, sans le SDK AWS : le
// module reste léger et seuls deux appels sont nécessaires (ListResourceRecordSets et
// ChangeResourceRecordSets).

const (
	route53DefaultBase = "https://route53.amazonaws.com"
	route53Region      = "us-east-1" // Route 53 est un service global, signé dans cette région
	route53Service     = "route53"
	route53APIVersion  = "/2013-04-01"
	route53Namespace   = "https://route53.amazonaws.com/doc/2013-04-01/"
)

type route53Provider struct {
	hostedZoneID string
	accessKey    string
	secretKey    string
	sessionToken string

	// Valeurs nulles par défaut ; les tests injectent les leurs.
	baseURL string
	client  *http.Client
	now     func() time.Time
}

func newRoute53Provider(p map[string]string) (DNSProvider, error) {
	if p["hosted_zone_id"] == "" {
		return nil, fmt.Errorf("route53: hosted_zone_id requis")
	}
	if p["access_key_id"] == "" || p["secret_access_key"] == "" {
		return nil, fmt.Errorf("route53: access_key_id et secret_access_key requis")
	}
	return &route53Provider{
		hostedZoneID: p["hosted_zone_id"],
		accessKey:    p["access_key_id"],
		secretKey:    p["secret_access_key"],
		sessionToken: p["session_token"],
	}, nil
}

type r53Record struct {
	Name    string   `xml:"Name"`
	Type    string   `xml:"Type"`
	TTL     int      `xml:"TTL"`
	Values  []string `xml:"ResourceRecords>ResourceRecord>Value"`
	XMLName xml.Name `xml:"ResourceRecordSet"`
}

type r53ChangeRequest struct {
	XMLName xml.Name  `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns   string    `xml:"xmlns,attr"`
	Action  string    `xml:"ChangeBatch>Changes>Change>Action"`
	Record  r53Record `xml:"ChangeBatch>Changes>Change>ResourceRecordSet"`
}

func (r *route53Provider) fqdn(domain string) string {
	return challengePrefix + "." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".") + "."
}

// existing retourne le jeu TXT de challenge déjà présent pour domain, nil s'il n'y en a pas.
func (r *route53Provider) existing(ctx context.Context, domain string) (*r53Record, error) {
	name := r.fqdn(domain)
	q := url.Values{"name": {name}, "type": {"TXT"}, "maxitems": {"1"}}
	var out struct {
		Sets []r53Record `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if err := r.call(ctx, http.MethodGet, "/hostedzone/"+r.hostedZoneID+"/rrset", q, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Sets {
		s := out.Sets[i]
		// Route 53 échappe certains caractères (« * » devient \052) ; pour _acme-challenge le nom
		// est renvoyé tel quel, en minuscules.
		if strings.EqualFold(s.Name, name) && s.Type == "TXT" {
			return &s, nil
		}
	}
	return nil, nil
}

func (r *route53Provider) change(ctx context.Context, action string, rec r53Record) error {
	body, err := xml.Marshal(r53ChangeRequest{Xmlns: route53Namespace, Action: action, Record: rec})
	if err != nil {
		return err
	}
	return r.call(ctx, http.MethodPost, "/hostedzone/"+r.hostedZoneID+"/rrset/", nil, append([]byte(xml.Header), body...), nil)
}

func quoteTXT(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// SetTXTRecord ajoute la valeur au jeu TXT de challenge. UPSERT remplace tout le jeu : les
// valeurs déjà présentes (wildcard + apex partagent le même nom) sont donc reprises.
func (r *route53Provider) SetTXTRecord(ctx context.Context, domain, value string) error {
	values := []string{quoteTXT(value)}
	cur, err := r.existing(ctx, domain)
	if err != nil {
		return err
	}
	if cur != nil {
		seen := map[string]bool{values[0]: true}
		for _, v := range cur.Values {
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	return r.change(ctx, "UPSERT", r53Record{Name: r.fqdn(domain), Type: "TXT", TTL: 60, Values: values})
}

// DeleteTXTRecord supprime le jeu TXT de challenge. Route 53 exige de rejouer ses valeurs et son
// TTL exacts : on les relit d'abord. Rien à supprimer n'est pas une erreur.
func (r *route53Provider) DeleteTXTRecord(ctx context.Context, domain string) error {
	cur, err := r.existing(ctx, domain)
	if err != nil || cur == nil {
		return err
	}
	return r.change(ctx, "DELETE", *cur)
}

func (r *route53Provider) call(ctx context.Context, method, path string, query url.Values, body []byte, out any) error {
	base := route53DefaultBase
	if r.baseURL != "" {
		base = strings.TrimRight(r.baseURL, "/")
	}
	u := base + route53APIVersion + path
	if len(query) > 0 {
		u += "?" + sigV4Query(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	t := now().UTC()
	headers := map[string]string{"host": req.URL.Host, "x-amz-date": t.Format("20060102T150405Z")}
	if r.sessionToken != "" {
		headers["x-amz-security-token"] = r.sessionToken
	}
	auth, _ := sigV4(method, req.URL.Path, query, headers, body, r.accessKey, r.secretKey, route53Region, route53Service, t)
	req.Header.Set("X-Amz-Date", headers["x-amz-date"])
	if r.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", r.sessionToken)
	}
	req.Header.Set("Authorization", auth)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/xml")
	}
	resp, err := httpClient(r.client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("route53: HTTP %d: %s", resp.StatusCode, bodyText(resp.Body))
	}
	if out != nil {
		return xml.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// sigV4Query encode les paramètres comme l'exige la signature : clés triées, encodage RFC 3986.
func sigV4Query(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, sigV4Escape(k)+"="+sigV4Escape(v))
		}
	}
	return strings.Join(parts, "&")
}

func sigV4Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// sigV4 calcule l'en-tête Authorization (AWS Signature Version 4). headers contient les en-têtes
// à signer, noms en minuscules : « host » et « x-amz-date » au minimum. Retourne aussi le
// condensat de la requête canonique, utile pour les vecteurs de test publiés par AWS.
func sigV4(method, path string, query url.Values, headers map[string]string, payload []byte,
	accessKey, secretKey, region, service string, t time.Time) (authorization, canonicalHash string) {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	if path == "" {
		path = "/"
	}
	payloadHash := sha256.Sum256(payload)
	canonical := strings.Join([]string{
		method, path, sigV4Query(query), canonHeaders.String(), signedHeaders, hex.EncodeToString(payloadHash[:]),
	}, "\n")
	canonSum := sha256.Sum256([]byte(canonical))
	canonicalHash = hex.EncodeToString(canonSum[:])

	amzDate := t.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + canonicalHash

	key := hmacSHA256([]byte("AWS4"+secretKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	authorization = "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return authorization, canonicalHash
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
