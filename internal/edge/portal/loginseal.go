// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"golang.org/x/crypto/hkdf"
)

// Scellement des secrets des logins préconfigurés (ADR 0025). L'Admin saisit un mot de passe ou une clé, mais ne doit jamais
// le stocker ni le relayer en clair : le navigateur (ou la CLI) le chiffre pour la passerelle, qui seule sait l'ouvrir.
//
// Schéma ECIES : ECDH P-256 avec une clé éphémère de l'émetteur, HKDF-SHA256 (sel = clé éphémère, info = loginSealInfo), puis
// AES-256-GCM. La paire de la passerelle est dérivée de sa clé maître de portail : tous les membres d'un groupe HA, qui la
// partagent déjà, ouvrent les mêmes secrets. WebCrypto sait faire chacune de ces étapes, d'où P-256 plutôt qu'X25519.

const (
	loginSealInfo = "goproxify-portal-login-seal/v1"
	loginSealSalt = "goproxify-portal-login-seal"
	loginSealVer  = 1
)

// LoginSecret est ce qui s'ouvre d'un login : mot de passe, clé privée, ou les deux.
type LoginSecret struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// Empty : aucun secret.
func (s LoginSecret) Empty() bool { return s.Password == "" && s.PrivateKey == "" }

// SealedSecret est l'enveloppe qui voyage de l'émetteur à la passerelle, via l'Admin, qui ne la lit pas.
type SealedSecret struct {
	V     int    `json:"v"`
	EPK   string `json:"epk"`   // base64 : point P-256 non compressé (65 octets) de la clé éphémère
	Nonce string `json:"nonce"` // base64 : 12 octets
	CT    string `json:"ct"`    // base64 : AES-GCM (texte chiffré + étiquette)
}

func loginSealPrivateKey(secret string) (*ecdh.PrivateKey, error) {
	for ctr := byte(0); ctr < 16; ctr++ {
		r := hkdf.New(sha256.New, []byte(secret), []byte(loginSealSalt), []byte{'p', '2', '5', '6', ctr})
		var b [32]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		if k, err := ecdh.P256().NewPrivateKey(b[:]); err == nil {
			return k, nil // un scalaire hors du corps est rarissime : on passe au compteur suivant
		}
	}
	return nil, errors.New("dérivation de la clé de scellement impossible")
}

// LoginSealPublicKey retourne la clé publique de scellement (base64, point non compressé) dérivée de la clé maître du portail.
func LoginSealPublicKey(masterSecret string) (string, error) {
	if masterSecret == "" {
		return "", errNoMasterKey
	}
	k, err := loginSealPrivateKey(masterSecret)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func loginSealKDF(shared, epk []byte) ([32]byte, error) {
	var key [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, epk, []byte(loginSealInfo)), key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// SealLoginSecret chiffre un secret pour la passerelle dont on connaît la clé publique. Sert à la CLI et aux tests ; le
// navigateur fait la même chose avec WebCrypto. Retourne l'enveloppe en JSON.
func SealLoginSecret(pubB64 string, s LoginSecret) (string, error) {
	if s.Empty() {
		return "", errors.New("secret vide")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return "", fmt.Errorf("clé publique illisible : %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return "", fmt.Errorf("clé publique invalide : %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return "", err
	}
	epk := eph.PublicKey().Bytes()
	key, err := loginSealKDF(shared, epk)
	if err != nil {
		return "", err
	}
	plain, _ := json.Marshal(s)
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	env := SealedSecret{
		V: loginSealVer, EPK: base64.StdEncoding.EncodeToString(epk),
		Nonce: base64.StdEncoding.EncodeToString(nonce), CT: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, nil)),
	}
	out, _ := json.Marshal(env)
	return string(out), nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ValidSealedSecret contrôle la forme d'une enveloppe sans pouvoir l'ouvrir (l'Admin n'a pas la clé) : version connue, point
// P-256 valide, nonce de 12 octets, texte chiffré plus long que l'étiquette.
func ValidSealedSecret(sealed string) error {
	var env SealedSecret
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return errors.New("secret scellé illisible")
	}
	if env.V != loginSealVer {
		return fmt.Errorf("version de scellement inconnue : %d", env.V)
	}
	epk, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return errors.New("clé éphémère illisible")
	}
	if _, err := ecdh.P256().NewPublicKey(epk); err != nil {
		return errors.New("clé éphémère invalide")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		return errors.New("nonce invalide")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil || len(ct) <= 16 {
		return errors.New("texte chiffré invalide")
	}
	return nil
}

// OpenLoginSecret ouvre une enveloppe avec la clé maître courante, puis avec les anciennes (rotation du secret d'appairage).
func OpenLoginSecret(masterSecrets []string, sealed string) (LoginSecret, error) {
	var env SealedSecret
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return LoginSecret{}, errors.New("secret scellé illisible")
	}
	if env.V != loginSealVer {
		return LoginSecret{}, fmt.Errorf("version de scellement inconnue : %d", env.V)
	}
	epk, err1 := base64.StdEncoding.DecodeString(env.EPK)
	nonce, err2 := base64.StdEncoding.DecodeString(env.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(env.CT)
	if err1 != nil || err2 != nil || err3 != nil {
		return LoginSecret{}, errors.New("secret scellé illisible")
	}
	pub, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return LoginSecret{}, errors.New("clé éphémère invalide")
	}
	for _, m := range masterSecrets {
		if m == "" {
			continue
		}
		priv, err := loginSealPrivateKey(m)
		if err != nil {
			continue
		}
		shared, err := priv.ECDH(pub)
		if err != nil {
			continue
		}
		key, err := loginSealKDF(shared, epk)
		if err != nil {
			continue
		}
		gcm, err := newGCM(key)
		if err != nil || len(nonce) != gcm.NonceSize() {
			continue
		}
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			continue
		}
		var s LoginSecret
		if err := json.Unmarshal(plain, &s); err != nil {
			return LoginSecret{}, errors.New("secret illisible")
		}
		return s, nil
	}
	return LoginSecret{}, errors.New("secret scellé pour une autre clé : le ressaisir dans l'Admin")
}

// loginSealSecrets liste les clés maîtres qui peuvent ouvrir un secret : la courante, puis les anciennes secrets d'appairage.
func loginSealSecrets(current string) []string {
	out := []string{current}
	for _, old := range strings.Split(os.Getenv(edgecache.PreviousSecretsEnv), ",") {
		if old = strings.TrimSpace(old); old != "" && old != current {
			out = append(out, old)
		}
	}
	return out
}
