package domains

// Passkey (WebAuthn) challenge (Batch 8).
//
// An optional alternative to the captcha challenge at Stage 3:
// a visitor with an enrolled passkey proves possession of the
// private key through the browser's WebAuthn API instead of
// solving a captcha. Only the assertion (authentication)
// ceremony is implemented; the registration ceremony is not —
// credentials are enrolled out of band through the control API
// (ENROLL_PASSKEY), which stores public-key material only.
//
// What is verified, server-side, for every assertion:
//   - clientDataJSON is well-formed JSON with type
//     "webauthn.get", the exact challenge the proxy issued, and
//     an origin from the operator's allowlist (default:
//     "https://<rpId>").
//   - authenticatorData carries SHA-256(rpId) as its first 32
//     bytes and the User Present flag.
//   - the signature over authenticatorData ||
//     SHA-256(clientDataJSON) verifies with the enrolled public
//     key: ES256 (ECDSA P-256, ASN.1 DER signature as WebAuthn
//     specifies) or RS256 (PKCS#1 v1.5, SHA-256).
//   - the signature counter is monotonic when both the stored
//     and presented counters are non-zero (a non-increasing
//     counter signals a cloned authenticator).
//
// Credentials live in a JSON file named by the config
// (passkey.credentialsFile), holding only public keys: the
// credential ID, the public key in JWK form, an opaque user
// handle, a label, and the last signature counter. No private
// key material is ever stored or accepted. The file is loaded
// at startup and on reload; enrollment writes it atomically.
//
// The passkey page is served only when passkeys are enabled,
// an RP ID is configured, and at least one credential is
// enrolled. Otherwise the captcha challenge is used, so the
// passkey flow can never become the only challenge path by
// accident: an operator with no enrolled credentials always
// keeps the captcha fallback.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

// PasskeyConfig is the per-domain passkey configuration
// (domain.passkey). RPID is the relying-party ID (usually the
// domain name); RPName is the display name shown by the
// browser; Origins lists the allowed origins (default
// "https://<rpId>" when empty); CredentialsFile is the JSON
// credential store, relative to the proxy working directory.
type PasskeyConfig struct {
	Enabled         bool     `json:"enabled"`
	RPID            string   `json:"rpId"`
	RPName          string   `json:"rpName"`
	Origins         []string `json:"origins"`
	CredentialsFile string   `json:"credentialsFile"`
}

// PasskeyPublicKey is one enrolled credential's public key in
// JWK form. EC keys use Kty "EC", Crv "P-256", X, Y; RSA keys
// use Kty "RSA", N, E. All values are base64url.
type PasskeyPublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PasskeyCredential is one enrolled credential. Only public-key
// material is stored; SignCount is the last counter seen in a
// verified assertion.
type PasskeyCredential struct {
	CredentialID string           `json:"credentialId"`
	PublicKey    PasskeyPublicKey `json:"publicKey"`
	UserHandle   string           `json:"userHandle,omitempty"`
	Label        string           `json:"label,omitempty"`
	SignCount    uint32           `json:"signCount"`
}

// PasskeyStore is the loaded credential set for one domain. It
// is safe for concurrent use; enrollment mutates it in place so
// API writes are visible to the request path without a reload.
type PasskeyStore struct {
	mu          sync.Mutex
	file        string
	credentials []PasskeyCredential
	byID        map[string]int
}

// NewPasskeyStore loads the credential file, or returns nil
// when passkeys are disabled, no RP ID is set, or no file is
// named. A missing file means zero credentials (the captcha
// fallback applies); an unreadable or malformed file logs a
// warning and also yields zero credentials, never a crash.
func NewPasskeyStore(domainName string, cfg PasskeyConfig) *PasskeyStore {
	if !cfg.Enabled || cfg.RPID == "" || cfg.CredentialsFile == "" {
		return nil
	}
	store := &PasskeyStore{file: cfg.CredentialsFile, byID: map[string]int{}}
	data, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Println("[ ! ] [ passkey credentials unreadable for " + domainName + ": " + err.Error() + "; captcha fallback applies ]")
		}
		return store
	}
	var creds []PasskeyCredential
	if err := json.Unmarshal(data, &creds); err != nil {
		fmt.Println("[ ! ] [ passkey credentials malformed for " + domainName + ": " + err.Error() + "; captcha fallback applies ]")
		return store
	}
	for _, cred := range creds {
		if cred.CredentialID == "" || !validPasskeyKey(cred.PublicKey) {
			continue
		}
		store.byID[cred.CredentialID] = len(store.credentials)
		store.credentials = append(store.credentials, cred)
	}
	return store
}

// validPasskeyKey reports whether a JWK public key is one the
// verifier supports: P-256 EC or RSA with decodable values.
func validPasskeyKey(key PasskeyPublicKey) bool {
	switch key.Kty {
	case "EC":
		if key.Crv != "P-256" {
			return false
		}
		_, errX := base64.RawURLEncoding.DecodeString(key.X)
		_, errY := base64.RawURLEncoding.DecodeString(key.Y)
		return errX == nil && errY == nil
	case "RSA":
		_, errN := base64.RawURLEncoding.DecodeString(key.N)
		_, errE := base64.RawURLEncoding.DecodeString(key.E)
		return errN == nil && errE == nil
	default:
		return false
	}
}

// Count reports the number of enrolled credentials.
func (s *PasskeyStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.credentials)
}

// CredentialIDs returns the enrolled credential IDs, for the
// allowCredentials list on the challenge page.
func (s *PasskeyStore) CredentialIDs() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.credentials))
	for _, cred := range s.credentials {
		ids = append(ids, cred.CredentialID)
	}
	return ids
}

// List returns a copy of the enrolled credentials.
func (s *PasskeyStore) List() []PasskeyCredential {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PasskeyCredential, len(s.credentials))
	copy(out, s.credentials)
	return out
}

// Enroll adds a credential and persists the file. A duplicate
// credential ID is rejected. The file write is atomic (temp
// file + rename in the same directory).
func (s *PasskeyStore) Enroll(cred PasskeyCredential) error {
	if s == nil {
		return errors.New("passkey store not configured")
	}
	if cred.CredentialID == "" || !validPasskeyKey(cred.PublicKey) {
		return errors.New("invalid credential")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[cred.CredentialID]; exists {
		return errors.New("credential already enrolled")
	}
	s.byID[cred.CredentialID] = len(s.credentials)
	s.credentials = append(s.credentials, cred)
	if err := s.persistLocked(); err != nil {
		delete(s.byID, cred.CredentialID)
		s.credentials = s.credentials[:len(s.credentials)-1]
		return err
	}
	return nil
}

// Remove deletes a credential by ID and persists the file.
func (s *PasskeyStore) Remove(credentialID string) error {
	if s == nil {
		return errors.New("passkey store not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, exists := s.byID[credentialID]
	if !exists {
		return errors.New("credential not found")
	}
	removed := s.credentials[index]
	s.credentials = append(s.credentials[:index], s.credentials[index+1:]...)
	delete(s.byID, credentialID)
	for i := index; i < len(s.credentials); i++ {
		s.byID[s.credentials[i].CredentialID] = i
	}
	if err := s.persistLocked(); err != nil {
		s.credentials = append(s.credentials, PasskeyCredential{})
		copy(s.credentials[index+1:], s.credentials[index:])
		s.credentials[index] = removed
		s.byID[credentialID] = index
		for i := index + 1; i < len(s.credentials); i++ {
			s.byID[s.credentials[i].CredentialID] = i
		}
		return err
	}
	return nil
}

// persistLocked writes the credential file atomically. The
// caller must hold s.mu.
func (s *PasskeyStore) persistLocked() error {
	data, err := json.MarshalIndent(s.credentials, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.file)
	tmp, err := os.CreateTemp(dir, ".passkeys-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.file)
}

// lookup returns a copy of the credential with this ID.
func (s *PasskeyStore) lookup(credentialID string) (PasskeyCredential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.byID[credentialID]
	if !ok {
		return PasskeyCredential{}, false
	}
	return s.credentials[index], true
}

// noteSignCount records a new signature counter after a
// verified assertion. Persistence failures are reported but do
// not invalidate the verification that already succeeded.
func (s *PasskeyStore) noteSignCount(credentialID string, count uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.byID[credentialID]
	if !ok {
		return errors.New("credential not found")
	}
	s.credentials[index].SignCount = count
	return s.persistLocked()
}

// VerifyAssertion checks a WebAuthn assertion against an
// enrolled credential. challenge is the exact challenge bytes
// the proxy issued; origins is the allowlist (empty means the
// default "https://<rpId>"). clientDataJSON, authenticatorData,
// and signature are the raw decoded assertion parts. On
// success the stored signature counter is advanced.
func (s *PasskeyStore) VerifyAssertion(rpID string, origins []string, challenge []byte, credentialID string, clientDataJSON, authenticatorData, signature []byte) bool {
	if s == nil || rpID == "" || len(challenge) == 0 {
		return false
	}
	cred, ok := s.lookup(credentialID)
	if !ok {
		return false
	}
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return false
	}
	if clientData.Type != "webauthn.get" {
		return false
	}
	presented, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		// Some clients send padded base64url; accept both.
		presented, err = base64.URLEncoding.DecodeString(clientData.Challenge)
		if err != nil {
			return false
		}
	}
	if string(presented) != string(challenge) {
		return false
	}
	if !originAllowed(clientData.Origin, rpID, origins) {
		return false
	}
	if len(authenticatorData) < 37 {
		return false
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if string(authenticatorData[:32]) != string(rpHash[:]) {
		return false
	}
	const flagUserPresent = 0x01
	if authenticatorData[32]&flagUserPresent == 0 {
		return false
	}
	signCount := uint32(authenticatorData[33])<<24 | uint32(authenticatorData[34])<<16 | uint32(authenticatorData[35])<<8 | uint32(authenticatorData[36])
	if cred.SignCount > 0 && signCount > 0 && signCount <= cred.SignCount {
		return false
	}
	clientHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(clientHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, clientHash[:]...)
	if !verifyAssertionSignature(cred.PublicKey, signed, signature) {
		return false
	}
	if signCount > 0 {
		_ = s.noteSignCount(credentialID, signCount)
	}
	return true
}

// originAllowed reports whether origin is on the allowlist, or
// equals the default "https://<rpId>" when no origins are
// configured.
func originAllowed(origin, rpID string, origins []string) bool {
	if len(origins) == 0 {
		return origin == "https://"+rpID
	}
	for _, allowed := range origins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// verifyAssertionSignature verifies a WebAuthn assertion
// signature. ES256 signatures are ASN.1 DER encoded (unlike
// JWS, which uses raw R||S); RS256 uses PKCS#1 v1.5.
func verifyAssertionSignature(key PasskeyPublicKey, signed, signature []byte) bool {
	digest := sha256.Sum256(signed)
	switch key.Kty {
	case "EC":
		if key.Crv != "P-256" {
			return false
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return false
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return false
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		var parsed struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &parsed); err != nil {
			return false
		}
		return ecdsa.Verify(pub, digest[:], parsed.R, parsed.S)
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return false
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes)}
		pub.E = 0
		for _, b := range eBytes {
			pub.E = pub.E<<8 | int(b)
		}
		if pub.E == 0 {
			return false
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil
	default:
		return false
	}
}
