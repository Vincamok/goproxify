package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func frame(flag byte, payload string) []byte {
	b := []byte{flag, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}

func TestGRPCWebRequestConversion(t *testing.T) {
	msg := frame(0, "hello")
	r := httptest.NewRequest("POST", "/pkg.Svc/Method", strings.NewReader(base64.StdEncoding.EncodeToString(msg)))
	r.Header.Set("Content-Type", "application/grpc-web-text+proto")
	r.Header.Set("X-Grpc-Web", "1")
	mode := grpcWebMode(r)
	if mode != 2 {
		t.Fatalf("mode = %d", mode)
	}
	r = toGRPCRequest(r, mode)
	got, _ := io.ReadAll(r.Body)
	if !bytes.Equal(got, msg) {
		t.Fatalf("corps décodé = %x, attendu %x", got, msg)
	}
	if r.Header.Get("Content-Type") != "application/grpc" || r.Header.Get("Te") != "trailers" || r.Header.Get("X-Grpc-Web") != "" {
		t.Fatalf("en-têtes : %v", r.Header)
	}
	if r.Context().Value(grpcWebKey{}) != 2 {
		t.Fatal("mode absent du contexte")
	}
}

func grpcResp(mode int, body []byte, headers, trailers http.Header) *http.Response {
	req := httptest.NewRequest("POST", "/", nil).WithContext(context.WithValue(context.Background(), grpcWebKey{}, mode))
	headers.Set("Content-Type", "application/grpc")
	return &http.Response{Request: req, Header: headers, Trailer: trailers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func TestGRPCWebResponseBinary(t *testing.T) {
	msg := frame(0, "reply")
	trailers := http.Header{}
	resp := grpcResp(1, msg, http.Header{}, trailers)
	fromGRPCResponse(resp)
	trailers.Set("Grpc-Status", "0") // renseignés par le transport après la lecture du corps
	if resp.Header.Get("Content-Type") != "application/grpc-web+proto" || resp.Trailer != nil {
		t.Fatalf("en-têtes : %v trailer=%v", resp.Header, resp.Trailer)
	}
	got, _ := io.ReadAll(resp.Body)
	want := append(append([]byte{}, msg...), frame(0x80, "grpc-status: 0\r\n")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("corps = %q, attendu %q", got, want)
	}
}

func TestGRPCWebResponseTextTrailersOnly(t *testing.T) {
	h := http.Header{}
	h.Set("Grpc-Status", "5")
	h.Set("Grpc-Message", "not found")
	resp := grpcResp(2, nil, h, http.Header{})
	fromGRPCResponse(resp)
	enc, _ := io.ReadAll(resp.Body)
	got, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		t.Fatalf("base64 invalide : %v", err)
	}
	if want := frame(0x80, "grpc-message: not found\r\ngrpc-status: 5\r\n"); !bytes.Equal(got, want) {
		t.Fatalf("trame = %q, attendue %q", got, want)
	}
	if resp.Header.Get("Content-Type") != "application/grpc-web-text+proto" {
		t.Fatalf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
}

func TestGRPCWebIgnoresNonGRPCResponse(t *testing.T) {
	resp := grpcResp(1, []byte("x"), http.Header{}, nil)
	resp.Header.Set("Content-Type", "text/plain")
	fromGRPCResponse(resp)
	if b, _ := io.ReadAll(resp.Body); string(b) != "x" {
		t.Fatalf("corps modifié : %q", b)
	}
}
