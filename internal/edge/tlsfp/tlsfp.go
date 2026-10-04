// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package tlsfp calcule les empreintes TLS JA3 et JA4 d'un ClientHello et les transporte
// jusqu'aux middlewares via le contexte de la requête.
package tlsfp

import (
	"context"
	"crypto/md5" //nolint:gosec // JA3 est défini sur MD5 ; ce n'est pas une primitive de sécurité ici
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Fingerprint est l'empreinte d'un ClientHello TLS.
type Fingerprint struct {
	JA3     string // chaîne JA3 brute (avant MD5)
	JA3Hash string // MD5 de JA3, 32 caractères hexadécimaux
	JA4     string // ex. t13d1516h2_8daaf6152771_02713d6af862
}

type ctxKey struct{}

func WithContext(ctx context.Context, fp *Fingerprint) context.Context {
	if fp == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, fp)
}

// FromContext retourne l'empreinte de la connexion TLS de la requête (nil pour du HTTP clair ou QUIC).
func FromContext(ctx context.Context) *Fingerprint {
	fp, _ := ctx.Value(ctxKey{}).(*Fingerprint)
	return fp
}

// Matches indique si l'empreinte correspond à l'une des signatures (JA3 MD5 ou JA4, insensible à la casse).
func (f *Fingerprint) Matches(signatures map[string]struct{}) bool {
	if f == nil || len(signatures) == 0 {
		return false
	}
	_, ja3 := signatures[strings.ToLower(f.JA3Hash)]
	_, ja4 := signatures[strings.ToLower(f.JA4)]
	return ja3 || ja4
}

func isGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.bad = true
		r.b = nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return uint16(v[0])<<8 | uint16(v[1])
	}
	return 0
}

// Parse calcule les empreintes depuis un enregistrement TLS complet (en-tête de 5 octets inclus)
// contenant un ClientHello. Retourne nil si les octets ne sont pas un ClientHello valide.
func Parse(record []byte) *Fingerprint {
	if len(record) < 9 || record[0] != 0x16 {
		return nil
	}
	recLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+recLen {
		return nil
	}
	hs := record[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil
	}
	r := &reader{b: hs[4 : 4+hsLen]}

	legacyVersion := r.u16()
	r.take(32) // random
	r.take(r.u8())
	csLen := int(r.u16())
	csBytes := r.take(csLen)
	r.take(r.u8()) // compression
	if r.bad {
		return nil
	}

	var ciphers []uint16
	for i := 0; i+1 < len(csBytes); i += 2 {
		if v := uint16(csBytes[i])<<8 | uint16(csBytes[i+1]); !isGrease(v) {
			ciphers = append(ciphers, v)
		}
	}

	var (
		extTypes    []uint16
		groups      []uint16
		pointFmts   []int
		sigAlgs     []uint16
		versions    []uint16
		alpnFirst   string
		hasSNI      bool
		extTotalLen = int(r.u16())
	)
	exts := &reader{b: r.take(extTotalLen)}
	for len(exts.b) >= 4 && !exts.bad {
		typ := exts.u16()
		data := &reader{b: exts.take(int(exts.u16()))}
		if exts.bad {
			break
		}
		if isGrease(typ) {
			continue
		}
		extTypes = append(extTypes, typ)
		switch typ {
		case 0x0000:
			hasSNI = true
		case 0x000a: // supported_groups
			list := &reader{b: data.take(int(data.u16()))}
			for len(list.b) >= 2 {
				if v := list.u16(); !isGrease(v) {
					groups = append(groups, v)
				}
			}
		case 0x000b: // ec_point_formats
			list := &reader{b: data.take(data.u8())}
			for len(list.b) >= 1 {
				pointFmts = append(pointFmts, list.u8())
			}
		case 0x000d: // signature_algorithms
			list := &reader{b: data.take(int(data.u16()))}
			for len(list.b) >= 2 {
				sigAlgs = append(sigAlgs, list.u16())
			}
		case 0x0010: // ALPN
			list := &reader{b: data.take(int(data.u16()))}
			if n := list.u8(); !list.bad {
				alpnFirst = string(list.take(n))
			}
		case 0x002b: // supported_versions
			list := &reader{b: data.take(data.u8())}
			for len(list.b) >= 2 {
				if v := list.u16(); !isGrease(v) {
					versions = append(versions, v)
				}
			}
		}
	}

	fp := &Fingerprint{}

	// JA3 : version,ciphers,extensions,groups,point formats (GREASE retiré).
	fp.JA3 = fmt.Sprintf("%d,%s,%s,%s,%s",
		legacyVersion, joinDec(ciphers), joinDec(extTypes), joinDec(groups), joinInts(pointFmts))
	sum := md5.Sum([]byte(fp.JA3)) //nolint:gosec
	fp.JA3Hash = hex.EncodeToString(sum[:])

	// JA4 : a_b_c.
	version := legacyVersion
	if len(versions) > 0 {
		version = 0
		for _, v := range versions {
			version = max(version, v)
		}
	}
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(version), sni, min(len(ciphers), 99), min(len(extTypes), 99), ja4ALPN(alpnFirst))

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	b := hash12(joinHex(sortedCiphers), len(ciphers) == 0)

	var sortedExts []uint16
	for _, t := range extTypes {
		if t != 0x0000 && t != 0x0010 {
			sortedExts = append(sortedExts, t)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	cInput := joinHex(sortedExts)
	if len(sigAlgs) > 0 {
		cInput += "_" + joinHex(sigAlgs)
	}
	c := hash12(cInput, len(extTypes) == 0)

	fp.JA4 = a + "_" + b + "_" + c
	return fp
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

// ja4ALPN : premier et dernier caractère du premier protocole ALPN ("00" si absent).
func ja4ALPN(proto string) string {
	if proto == "" {
		return "00"
	}
	first, last := proto[0], proto[len(proto)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte{first, last})
	return string([]byte{h[0], h[3]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func hash12(s string, empty bool) string {
	if empty {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func joinDec(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, "-")
}

func joinHex(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}
