// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logexport produit l'export complet des logs d'une passerelle pour une procédure légale (ADR 0012) : les
// lignes d'une plage, l'IP réelle déchiffrée par la clé locale, un manifeste signé par une clé de la passerelle et une
// sortie chiffrée par mot de passe. Tout se fait en local, sans l'Admin.
package logexport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Format du fichier chiffré : « GPXE1\n », le coût scrypt (log2 de N, un octet), 16 octets de sel, puis des blocs
// [longueur sur 4 octets][AES-256-GCM] de 64 Kio en clair au plus. Le nonce est le numéro du bloc, la donnée
// authentifiée marque le dernier bloc : un bloc retiré, déplacé ou une fin coupée est refusé.
const (
	magic      = "GPXE1\n"
	chunkSize  = 64 << 10
	scryptLogN = 15
	saltSize   = 16
	// MinPasswordLen : un mot de passe plus court est refusé.
	MinPasswordLen = 12
)

// ErrDecrypt : mot de passe incorrect, ou fichier altéré.
var ErrDecrypt = errors.New("déchiffrement impossible : mot de passe incorrect ou fichier altéré")

func deriveKey(password string, salt []byte, logN byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<logN, 8, 1, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

type encWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	buf    []byte
	ctr    uint64
	closed bool
}

// NewEncryptWriter chiffre ce qui lui est écrit avec une clé dérivée du mot de passe. Close écrit le dernier bloc :
// sans lui le fichier est refusé au déchiffrement.
func NewEncryptWriter(w io.Writer, password string) (io.WriteCloser, error) {
	if len(password) < MinPasswordLen {
		return nil, fmt.Errorf("mot de passe trop court (%d caractères au moins)", MinPasswordLen)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt, scryptLogN)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	header := append([]byte(magic), scryptLogN)
	if _, err := w.Write(append(header, salt...)); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead}, nil
}

func (e *encWriter) seal(plain []byte, final bool) error {
	aad := []byte{0}
	if final {
		aad[0] = 1
	}
	ct := e.aead.Seal(nil, nonce(e.ctr), plain, aad)
	e.ctr++
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := e.w.Write(l[:]); err != nil {
		return err
	}
	_, err := e.w.Write(ct)
	return err
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("écriture après Close")
	}
	e.buf = append(e.buf, p...)
	for len(e.buf) >= chunkSize {
		if err := e.seal(e.buf[:chunkSize], false); err != nil {
			return 0, err
		}
		e.buf = e.buf[chunkSize:]
	}
	return len(p), nil
}

func (e *encWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.seal(e.buf, true)
}

type decReader struct {
	r    io.Reader
	aead cipher.AEAD
	ctr  uint64
	out  []byte
	done bool
}

// NewDecryptReader relit un fichier produit par NewEncryptWriter.
func NewDecryptReader(r io.Reader, password string) (io.Reader, error) {
	header := make([]byte, len(magic)+1+saltSize)
	if _, err := io.ReadFull(r, header); err != nil || string(header[:len(magic)]) != magic {
		return nil, errors.New("ce n'est pas un fichier d'export chiffré GoProxify")
	}
	logN := header[len(magic)]
	if logN < 10 || logN > 22 {
		return nil, errors.New("paramètres de chiffrement hors limites")
	}
	key, err := deriveKey(password, header[len(magic)+1:], logN)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &decReader{r: r, aead: aead}, nil
}

func (d *decReader) next() error {
	var l [4]byte
	if _, err := io.ReadFull(d.r, l[:]); err != nil {
		return errors.New("fichier tronqué : le dernier bloc manque")
	}
	n := binary.BigEndian.Uint32(l[:])
	if n < uint32(d.aead.Overhead()) || n > chunkSize+uint32(d.aead.Overhead()) {
		return ErrDecrypt
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(d.r, ct); err != nil {
		return errors.New("fichier tronqué")
	}
	if pt, err := d.aead.Open(nil, nonce(d.ctr), ct, []byte{0}); err == nil {
		d.out = pt
	} else if pt, err := d.aead.Open(nil, nonce(d.ctr), ct, []byte{1}); err == nil {
		d.out, d.done = pt, true
		var extra [1]byte
		if k, _ := d.r.Read(extra[:]); k > 0 {
			return ErrDecrypt
		}
	} else {
		return ErrDecrypt
	}
	d.ctr++
	return nil
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.out) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}
