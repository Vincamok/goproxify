// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Types de destination externe.
const (
	DestDir    = "dir"    // dossier local ou monté (NFS, SMB, disque externe)
	DestWebDAV = "webdav" // serveur WebDAV (Nextcloud, ownCloud, NAS…)
	DestS3     = "s3"     // stockage compatible S3 (AWS, MinIO, Scaleway, OVH, Wasabi, B2…)
)

// maxObjectBytes borne ce qu'un pilote relit ou envoie en mémoire.
const maxObjectBytes = 1 << 30

// Driver écrit, relit et supprime des objets nommés sur une destination.
type Driver interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
}

var httpClient = &http.Client{Timeout: 10 * time.Minute}

// NewDriver construit le pilote d'une destination à partir de sa configuration.
func NewDriver(d Destination) (Driver, error) {
	c := d.Config
	switch d.Type {
	case DestDir:
		p := strings.TrimSpace(c["path"])
		if p == "" || !filepath.IsAbs(p) {
			return nil, errors.New("dossier : chemin absolu requis")
		}
		return dirDriver{root: filepath.Clean(p)}, nil
	case DestWebDAV:
		u, err := validHTTPURL(c["url"])
		if err != nil {
			return nil, fmt.Errorf("webdav : %w", err)
		}
		return webdavDriver{base: u, user: c["username"], pass: c["password"]}, nil
	case DestS3:
		u, err := validHTTPURL(c["endpoint"])
		if err != nil {
			return nil, fmt.Errorf("s3 : %w", err)
		}
		if c["bucket"] == "" || c["access_key"] == "" || c["secret_key"] == "" {
			return nil, errors.New("s3 : bucket, access_key et secret_key requis")
		}
		region := c["region"]
		if region == "" {
			region = "us-east-1"
		}
		return s3Driver{endpoint: u, region: region, bucket: c["bucket"], prefix: strings.Trim(c["prefix"], "/"),
			access: c["access_key"], secret: c["secret_key"], virtualHost: c["path_style"] == "false"}, nil
	}
	return nil, fmt.Errorf("type de destination inconnu : %q", d.Type)
}

func validHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("URL http(s) requise")
	}
	return u, nil
}

// cleanObjectName refuse tout nom qui sortirait du dossier de destination.
func cleanObjectName(name string) (string, error) {
	if name == "" || name != path.Base(name) || strings.ContainsAny(name, `\/`) || name == "." || name == ".." {
		return "", fmt.Errorf("nom d'objet invalide : %q", name)
	}
	return name, nil
}

// ── Dossier ───────────────────────────────────────────────────────────────────

type dirDriver struct{ root string }

func (d dirDriver) Put(_ context.Context, name string, data []byte) error {
	name, err := cleanObjectName(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.root, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.root, ".gpx-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(d.root, name))
}

func (d dirDriver) Get(_ context.Context, name string) ([]byte, error) {
	name, err := cleanObjectName(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(d.root, name))
}

func (d dirDriver) Delete(_ context.Context, name string) error {
	name, err := cleanObjectName(name)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(d.root, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ── WebDAV ────────────────────────────────────────────────────────────────────

type webdavDriver struct {
	base       *url.URL
	user, pass string
}

func (w webdavDriver) do(ctx context.Context, method, name string, body []byte) (*http.Response, error) {
	name, err := cleanObjectName(name)
	if err != nil {
		return nil, err
	}
	u := *w.base
	u.Path = strings.TrimRight(u.Path, "/") + "/" + name
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if w.user != "" {
		req.SetBasicAuth(w.user, w.pass)
	}
	return httpClient.Do(req)
}

func (w webdavDriver) Put(ctx context.Context, name string, data []byte) error {
	resp, err := w.do(ctx, http.MethodPut, name, data)
	return statusErr(resp, err, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

func (w webdavDriver) Get(ctx context.Context, name string) ([]byte, error) {
	resp, err := w.do(ctx, http.MethodGet, name, nil)
	return readBody(resp, err)
}

func (w webdavDriver) Delete(ctx context.Context, name string) error {
	resp, err := w.do(ctx, http.MethodDelete, name, nil)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil
	}
	return statusErr(resp, err, http.StatusOK, http.StatusNoContent)
}

// ── S3 (SigV4) ────────────────────────────────────────────────────────────────

type s3Driver struct {
	endpoint       *url.URL
	region, bucket string
	prefix         string
	access, secret string
	virtualHost    bool
}

func (s s3Driver) do(ctx context.Context, method, name string, body []byte) (*http.Response, error) {
	name, err := cleanObjectName(name)
	if err != nil {
		return nil, err
	}
	key := name
	if s.prefix != "" {
		key = s.prefix + "/" + name
	}
	u := *s.endpoint
	if s.virtualHost {
		u.Host = s.bucket + "." + u.Host
		u.Path = "/" + key
	} else {
		u.Path = "/" + s.bucket + "/" + key
	}
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	s.sign(req, body, time.Now().UTC())
	return httpClient.Do(req)
}

// sign applique AWS Signature Version 4 (en-têtes, sans paramètres de requête).
func (s s3Driver) sign(req *http.Request, body []byte, now time.Time) {
	payload := sha256Hex(body)
	date, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	req.Header.Set("x-amz-date", stamp)
	req.Header.Set("x-amz-content-sha256", payload)

	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		v := req.Host
		if n != "host" {
			v = req.Header.Get(n)
		}
		canonHeaders.WriteString(n + ":" + strings.TrimSpace(v) + "\n")
	}
	signed := strings.Join(names, ";")
	canon := strings.Join([]string{req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signed, payload}, "\n")

	scope := date + "/" + s.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + sha256Hex([]byte(canon))
	k := hmacSHA256([]byte("AWS4"+s.secret), date)
	k = hmacSHA256(k, s.region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.access, scope, signed, sig))
}

func (s s3Driver) Put(ctx context.Context, name string, data []byte) error {
	resp, err := s.do(ctx, http.MethodPut, name, data)
	return statusErr(resp, err, http.StatusOK)
}

func (s s3Driver) Get(ctx context.Context, name string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, name, nil)
	return readBody(resp, err)
}

func (s s3Driver) Delete(ctx context.Context, name string) error {
	resp, err := s.do(ctx, http.MethodDelete, name, nil)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil
	}
	return statusErr(resp, err, http.StatusOK, http.StatusNoContent)
}

// ── Utilitaires ───────────────────────────────────────────────────────────────

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg)) //nolint:errcheck
	return m.Sum(nil)
}

// statusErr referme la réponse et renvoie une erreur si le statut n'est pas attendu.
func statusErr(resp *http.Response, err error, ok ...int) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for _, c := range ok {
		if resp.StatusCode == c {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			return nil
		}
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("HTTP %d : %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func readBody(resp *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d : %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxObjectBytes))
}
