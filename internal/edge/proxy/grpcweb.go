package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"sort"
	"strings"
)

type grpcWebKey struct{}

// grpcWebMode : 0 = pas gRPC-Web, 1 = binaire, 2 = texte (base64).
func grpcWebMode(r *http.Request) int {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "application/grpc-web-text"):
		return 2
	case strings.HasPrefix(ct, "application/grpc-web"):
		return 1
	}
	return 0
}

// toGRPCRequest convertit une requête gRPC-Web en requête gRPC pour le backend. Le cadrage des
// messages est identique ; seul le mode texte demande un décodage base64 du corps.
func toGRPCRequest(r *http.Request, mode int) *http.Request {
	if mode == 2 && r.Body != nil {
		r.Body = io.NopCloser(base64.NewDecoder(base64.StdEncoding, newBase64Cleaner(r.Body)))
		r.ContentLength = -1
		r.Header.Del("Content-Length")
	}
	r.Header.Set("Content-Type", "application/grpc")
	r.Header.Set("Te", "trailers")
	r.Header.Del("X-Grpc-Web")
	return r.WithContext(context.WithValue(r.Context(), grpcWebKey{}, mode))
}

// newBase64Cleaner retire les sauts de ligne éventuels du flux base64.
func newBase64Cleaner(src io.Reader) io.Reader { return &cleaner{src: src} }

type cleaner struct{ src io.Reader }

func (c *cleaner) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	out := p[:0]
	for _, b := range p[:n] {
		if b != '\n' && b != '\r' {
			out = append(out, b)
		}
	}
	return len(out), err
}

// fromGRPCResponse adapte la réponse gRPC du backend : type de contenu gRPC-Web et trailers
// transmis dans une dernière trame (drapeau 0x80), comme l'attendent les navigateurs.
func fromGRPCResponse(resp *http.Response) {
	mode, _ := resp.Request.Context().Value(grpcWebKey{}).(int)
	if mode == 0 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc") {
		return
	}
	if mode == 2 {
		resp.Header.Set("Content-Type", "application/grpc-web-text+proto")
	} else {
		resp.Header.Set("Content-Type", "application/grpc-web+proto")
	}
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	body := newGRPCWebBody(resp, mode == 2)
	body.trailer = resp.Trailer
	resp.Trailer = nil
	resp.Body = body
}

type grpcWebBody struct {
	resp    *http.Response
	trailer http.Header
	src     io.ReadCloser
	buf     bytes.Buffer
	out     io.Writer
	enc     io.WriteCloser
	done    bool
}

func newGRPCWebBody(resp *http.Response, text bool) *grpcWebBody {
	b := &grpcWebBody{resp: resp, src: resp.Body}
	b.out = &b.buf
	if text {
		b.enc = base64.NewEncoder(base64.StdEncoding, &b.buf)
		b.out = b.enc
	}
	return b
}

func (b *grpcWebBody) Read(p []byte) (int, error) {
	tmp := make([]byte, 8192)
	for b.buf.Len() == 0 {
		if b.done {
			return 0, io.EOF
		}
		n, err := b.src.Read(tmp)
		_, _ = b.out.Write(tmp[:n])
		if err != nil {
			b.finish()
		}
	}
	return b.buf.Read(p)
}

// finish écrit la trame de trailers (lus après la fin du corps) et vide l'encodeur base64.
func (b *grpcWebBody) finish() {
	b.done = true
	trailers := http.Header{}
	for k, v := range b.trailer {
		trailers[k] = v
	}
	if len(trailers) == 0 { // « trailers-only » : le statut est dans les en-têtes
		for _, k := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
			if v := b.resp.Header.Values(k); len(v) > 0 {
				trailers[k] = v
			}
		}
	}
	keys := make([]string, 0, len(trailers))
	for k := range trailers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var payload bytes.Buffer
	for _, k := range keys {
		for _, v := range trailers[k] {
			payload.WriteString(strings.ToLower(k) + ": " + v + "\r\n")
		}
	}
	hdr := make([]byte, 5)
	hdr[0] = 0x80
	binary.BigEndian.PutUint32(hdr[1:], uint32(payload.Len()))
	_, _ = b.out.Write(hdr)
	_, _ = b.out.Write(payload.Bytes())
	if b.enc != nil {
		_ = b.enc.Close()
	}
}

func (b *grpcWebBody) Close() error { return b.src.Close() }
