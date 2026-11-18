package backup

// Passphrase encryption for backup secrets (Batch 6).
//
// Secrets are encrypted with AES-256-GCM; the key is derived
// from the operator's passphrase with scrypt (N=32768, r=8,
// p=1, 32-byte key) and a random 16-byte salt. The GCM
// additional authenticated data is a binding derived from the
// envelope's redacted config document (see configBinding in
// backup.go), which ties the secrets blob to its own backup:
// transplanting a blob onto a different config fails
// authentication.
//
// The passphrase is never stored. A wrong passphrase, a
// tampered blob, or a transplanted blob all fail decryption,
// and a failed restore changes nothing.
//
// Minimum passphrase length is 8 characters: scrypt makes
// guessing expensive, but a 1-character passphrase is still
// a 1-character passphrase.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// MinPassphraseLength is the shortest accepted backup
// passphrase.
const MinPassphraseLength = 8

const (
	scryptN      = 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// EncryptedSecrets is the encrypted secrets blob carried by
// an encrypted backup envelope. All byte fields are base64.
type EncryptedSecrets struct {
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// EncryptSecrets encrypts plaintext secrets under passphrase,
// bound to binding (the config binding from configBinding).
func EncryptSecrets(plaintext []byte, passphrase string, binding []byte) (*EncryptedSecrets, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, binding)
	return &EncryptedSecrets{
		KDF:        "scrypt",
		N:          scryptN,
		R:          scryptR,
		P:          scryptP,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// DecryptSecrets reverses EncryptSecrets. Any mismatch —
// wrong passphrase, tampered blob, wrong config binding, or
// unsupported parameters — returns an error.
func DecryptSecrets(enc *EncryptedSecrets, passphrase string, binding []byte) ([]byte, error) {
	if enc.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported KDF %q", enc.KDF)
	}
	// Bound the KDF parameters so a hostile backup cannot
	// demand absurd memory/CPU.
	if enc.N < 1024 || enc.N > 1<<20 || enc.N&(enc.N-1) != 0 || enc.R < 1 || enc.R > 64 || enc.P < 1 || enc.P > 16 {
		return nil, errors.New("unreasonable scrypt parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(enc.Salt)
	if err != nil || len(salt) == 0 || len(salt) > 64 {
		return nil, errors.New("invalid salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return nil, errors.New("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("invalid ciphertext")
	}
	key, err := scrypt.Key([]byte(passphrase), salt, enc.N, enc.R, enc.P, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, binding)
	if err != nil {
		return nil, errors.New("authentication failed (wrong passphrase or tampered backup)")
	}
	return plaintext, nil
}
