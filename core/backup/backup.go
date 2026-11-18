package backup

// Backup envelope and secret handling (Batch 6).
//
// A backup is a versioned JSON envelope carrying the full
// config.json document — which already contains the firewall
// rules, IP lists, and tenant assignments (all per-domain
// config) — plus the secrets, handled one of two ways:
//
//   - Redacted (default): every secret value is replaced by
//     the REDACTED placeholder, exactly as the CLI export
//     redacts. A redacted backup is safe to store or share,
//     and restoring it keeps the target instance's current
//     secrets: placeholder values are filled from the live
//     config. Restoring a redacted backup onto an instance
//     that has no value for a redacted field fails with the
//     field named, rather than bricking the instance.
//   - Encrypted (explicit opt-in): the redacted document plus
//     a separately encrypted blob holding the real secrets
//     (see crypto.go). Restoring decrypts with the operator's
//     passphrase and merges the secrets into the document.
//
// The secret path table below is the single source of truth
// for the document form. It mirrors the struct redactor in
// cli.go (redactConfigForExport) field for field: when a
// secret-bearing config field is added, it must be added in
// BOTH places. A mismatch fails closed on the backup side
// (an unlisted secret would ship in cleartext in a redacted
// backup), so keep the two lists in sync.
//
// What a backup does NOT contain: TLS certificate/key files,
// GeoIP databases, and custom challenge-template files. Those
// live outside config.json; copy them separately when
// migrating, and keep the config's paths valid on the target.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Format identifies backup envelopes. Version is the envelope
// schema version; restores reject anything else.
const (
	Format  = "sonushield-backup"
	Version = 1
)

// Placeholder replaces secret values in redacted documents.
// It matches cli.go's redactedSecret exactly.
const Placeholder = "REDACTED"

// SecretsMode records how an envelope carries secrets.
const (
	SecretsRedacted  = "redacted"
	SecretsEncrypted = "encrypted"
)

// Envelope is the backup file format.
type Envelope struct {
	Format    string            `json:"format"`
	Version   int               `json:"version"`
	Created   time.Time         `json:"created"`
	Secrets   string            `json:"secrets"`
	Config    json.RawMessage   `json:"config"`
	Encrypted *EncryptedSecrets `json:"encryptedSecrets,omitempty"`
}

// segment is one step of a secret path: a map key, or an array
// traversal (key + iterate all elements).
type segment struct {
	key     string
	isArray bool
}

func k(key string) segment   { return segment{key: key} }
func arr(key string) segment { return segment{key: key, isArray: true} }

// secretPaths lists every secret-bearing location in the
// config document. Map-valued leaves (secrets, apiRoles) are
// handled as whole maps; see walkSecretPaths.
var secretPaths = [][]segment{
	{k("proxy"), k("adminsecret")},
	{k("proxy"), k("apisecret")},
	{k("proxy"), k("secrets")},
	{k("proxy"), k("apiRoles")},
	{k("proxy"), k("sso"), k("clientSecret")},
	{k("proxy"), k("stripe"), k("secretKey")},
	{k("proxy"), arr("publicApiKeys"), k("key")},
	{k("proxy"), arr("eventWebhooks"), k("url")},
	{k("proxy"), arr("eventWebhooks"), k("secret")},
	{arr("domains"), k("webhook"), k("url")},
	{arr("domains"), k("telegram"), k("botToken")},
	{arr("domains"), k("email"), k("password")},
	{arr("domains"), k("twilio"), k("authToken")},
	{arr("domains"), k("challengeSecretKey")},
	{arr("domains"), k("jwtSecret")},
	{arr("domains"), k("originLockSecret")},
	{arr("domains"), k("signedURLSecret")},
	{arr("domains"), k("cloudflareApiToken")},
	{arr("domains"), arr("apiKeys"), k("key")},
}

// isMapLeaf reports whether a path ends at a whole-map secret
// (secrets/apiRoles), whose keys or values are all sensitive.
func isMapLeaf(path []segment) bool {
	last := path[len(path)-1].key
	return last == "secrets" || last == "apiRoles"
}

// parseDoc decodes a config document into generic maps,
// preserving number literals.
func parseDoc(data []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]interface{}
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func encodeDoc(doc map[string]interface{}) ([]byte, error) {
	return json.Marshal(doc)
}

// walkSecretPaths visits every secret leaf in doc, calling fn
// with the parent map, the leaf key, and whether the leaf is a
// whole map. Missing intermediate objects and non-object
// values are skipped silently: absent secrets need no work.
func walkSecretPaths(doc map[string]interface{}, fn func(parent map[string]interface{}, key string, mapLeaf bool)) {
	var walk func(node interface{}, path []segment)
	walk = func(node interface{}, path []segment) {
		if len(path) == 0 {
			return
		}
		seg := path[0]
		obj, ok := node.(map[string]interface{})
		if !ok {
			return
		}
		child, ok := obj[seg.key]
		if !ok {
			return
		}
		if seg.isArray {
			arr, ok := child.([]interface{})
			if !ok {
				return
			}
			for _, elem := range arr {
				if len(path) == 1 {
					continue
				}
				walk(elem, path[1:])
			}
			return
		}
		if len(path) == 1 {
			fn(obj, seg.key, isMapLeaf(path))
			return
		}
		walk(child, path[1:])
	}
	for _, path := range secretPaths {
		walk(doc, path)
	}
}

// redactValue replaces one string secret with the placeholder,
// leaving empty and non-string values untouched.
func redactValue(parent map[string]interface{}, key string) {
	if s, ok := parent[key].(string); ok && s != "" {
		parent[key] = Placeholder
	}
}

// redactMapLeaf redacts a whole-map secret: secrets values
// become placeholders; apiRoles keys (the secrets) become
// numbered placeholders, mirroring cli.go.
func redactMapLeaf(parent map[string]interface{}, key string) {
	m, ok := parent[key].(map[string]interface{})
	if !ok {
		return
	}
	if key == "secrets" {
		for k, v := range m {
			if s, ok := v.(string); ok && s != "" {
				m[k] = Placeholder
			}
		}
		return
	}
	// apiRoles: keys are secrets, values are roles. Rebuild
	// with numbered placeholders in role-sorted order so the
	// output is deterministic.
	roles := make([]string, 0, len(m))
	for _, v := range m {
		if s, ok := v.(string); ok {
			roles = append(roles, s)
		}
	}
	sort.Strings(roles)
	rebuilt := make(map[string]interface{}, len(roles))
	for i, role := range roles {
		rebuilt[fmt.Sprintf("%s-%d", Placeholder, i+1)] = role
	}
	parent[key] = rebuilt
}

// RedactDocument returns a copy of the config document with
// every secret value replaced by the placeholder. The input
// bytes are not modified.
func RedactDocument(data []byte) ([]byte, error) {
	doc, err := parseDoc(data)
	if err != nil {
		return nil, err
	}
	walkSecretPaths(doc, func(parent map[string]interface{}, key string, mapLeaf bool) {
		if mapLeaf {
			redactMapLeaf(parent, key)
		} else {
			redactValue(parent, key)
		}
	})
	return encodeDoc(doc)
}

// collectSecrets builds the partial secrets document: the same
// shape as the config, containing only non-empty secret
// values. Empty secrets are omitted (there is nothing to
// restore for them).
func collectSecrets(data []byte) (map[string]interface{}, error) {
	doc, err := parseDoc(data)
	if err != nil {
		return nil, err
	}
	secrets := map[string]interface{}{}
	var collect func(dst map[string]interface{}, node interface{}, path []segment)
	collect = func(dst map[string]interface{}, node interface{}, path []segment) {
		if len(path) == 0 {
			return
		}
		seg := path[0]
		obj, ok := node.(map[string]interface{})
		if !ok {
			return
		}
		child, ok := obj[seg.key]
		if !ok {
			return
		}
		if seg.isArray {
			arr, ok := child.([]interface{})
			if !ok {
				return
			}
			dstArr, _ := dst[seg.key].([]interface{})
			for len(dstArr) < len(arr) {
				dstArr = append(dstArr, map[string]interface{}{})
			}
			for i, elem := range arr {
				elemDst, _ := dstArr[i].(map[string]interface{})
				if elemDst == nil {
					elemDst = map[string]interface{}{}
					dstArr[i] = elemDst
				}
				collect(elemDst, elem, path[1:])
			}
			dst[seg.key] = dstArr
			return
		}
		if len(path) == 1 {
			if isMapLeaf(path) {
				if m, ok := child.(map[string]interface{}); ok && len(m) > 0 {
					dst[seg.key] = child
				}
				return
			}
			if s, ok := child.(string); ok && s != "" {
				dst[seg.key] = s
			}
			return
		}
		next, _ := dst[seg.key].(map[string]interface{})
		if next == nil {
			next = map[string]interface{}{}
			dst[seg.key] = next
		}
		collect(next, child, path[1:])
	}
	for _, path := range secretPaths {
		collect(secrets, doc, path)
	}
	return secrets, nil
}

// mapLeafPaths are the secret paths whose whole map is the
// secret: merging overwrites them instead of deep-merging,
// so no redacted key survives a restore.
var mapLeafPaths = map[string]bool{
	"proxy.secrets":  true,
	"proxy.apiRoles": true,
}

// mergeSecrets deep-merges the partial secrets document into
// the target document, overwriting values at secret paths and
// leaving everything else untouched. Arrays merge by index;
// whole-map secrets overwrite wholesale.
func mergeSecrets(doc, secrets map[string]interface{}) {
	mergeAt(doc, secrets, "")
}

func mergeAt(dst, src map[string]interface{}, prefix string) {
	for key, value := range src {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if mapLeafPaths[path] {
			dst[key] = value
			continue
		}
		srcObj, srcIsObj := value.(map[string]interface{})
		if srcIsObj {
			if dstObj, ok := dst[key].(map[string]interface{}); ok {
				mergeAt(dstObj, srcObj, path)
				continue
			}
			dst[key] = value
			continue
		}
		if srcArr, ok := value.([]interface{}); ok {
			if dstArr, ok := dst[key].([]interface{}); ok {
				for i, elem := range srcArr {
					if i >= len(dstArr) {
						break
					}
					elemObj, ok1 := elem.(map[string]interface{})
					dstElem, ok2 := dstArr[i].(map[string]interface{})
					if ok1 && ok2 {
						mergeAt(dstElem, elemObj, path)
					}
				}
				continue
			}
			dst[key] = value
			continue
		}
		dst[key] = value
	}
}

// fillPlaceholders replaces every placeholder in the backup
// document with the current instance's value at the same path.
// A placeholder with no current value is an error naming the
// path: restoring it would brick the instance.
func fillPlaceholders(backup, current map[string]interface{}) error {
	var firstErr error
	// Walk the backup with index-aware lookup: array paths
	// need the element index, so re-walk with position.
	var walkBoth func(bNode, cNode interface{}, path []segment, name string)
	walkBoth = func(bNode, cNode interface{}, path []segment, name string) {
		if firstErr != nil || len(path) == 0 {
			return
		}
		seg := path[0]
		bObj, ok := bNode.(map[string]interface{})
		if !ok {
			return
		}
		child, ok := bObj[seg.key]
		if !ok {
			return
		}
		if seg.isArray {
			bArr, ok := child.([]interface{})
			if !ok {
				return
			}
			var cArr []interface{}
			if cObj, ok := cNode.(map[string]interface{}); ok {
				cArr, _ = cObj[seg.key].([]interface{})
			}
			for i, elem := range bArr {
				var cElem interface{}
				if i < len(cArr) {
					cElem = cArr[i]
				}
				walkBoth(elem, cElem, path[1:], fmt.Sprintf("%s[%d]", name, i))
			}
			return
		}
		if len(path) == 1 {
			name = name + "." + seg.key
			cObj, _ := cNode.(map[string]interface{})
			var currentValue interface{}
			var hasCurrent bool
			if cObj != nil {
				currentValue, hasCurrent = cObj[seg.key]
			}
			if isMapLeaf(path) {
				if hasPlaceholderKey(child) {
					if !hasCurrent {
						firstErr = fmt.Errorf("backup redacts %s but this instance has no value for it (use an encrypted backup or set it first)", strings.TrimPrefix(name, "."))
						return
					}
					bObj[seg.key] = currentValue
				}
				return
			}
			if s, ok := child.(string); ok && s == Placeholder {
				currentStr, ok := currentValue.(string)
				if !hasCurrent || !ok || currentStr == "" {
					firstErr = fmt.Errorf("backup redacts %s but this instance has no value for it (use an encrypted backup or set it first)", strings.TrimPrefix(name, "."))
					return
				}
				bObj[seg.key] = currentStr
			}
			return
		}
		var cChild interface{}
		if cObj, ok := cNode.(map[string]interface{}); ok {
			cChild = cObj[seg.key]
		}
		walkBoth(child, cChild, path[1:], name+"."+seg.key)
	}
	for _, path := range secretPaths {
		walkBoth(backup, current, path, "")
		if firstErr != nil {
			return firstErr
		}
	}
	return nil
}

// hasPlaceholderKey reports whether a map leaf contains a
// redaction placeholder key (apiRoles form) or value.
func hasPlaceholderKey(node interface{}) bool {
	m, ok := node.(map[string]interface{})
	if !ok {
		return false
	}
	for k, v := range m {
		if k == Placeholder || strings.HasPrefix(k, Placeholder+"-") {
			return true
		}
		if s, ok := v.(string); ok && s == Placeholder {
			return true
		}
	}
	return false
}

// configBinding derives the encryption binding for a config
// document: the SHA-256 of its canonical re-marshal (sorted
// keys). Raw bytes cannot be the binding — envelope encoding
// re-indents the embedded document — but the canonical form
// is identical on both sides.
func configBinding(configDoc []byte) ([]byte, error) {
	doc, err := parseDoc(configDoc)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return []byte(hex.EncodeToString(sum[:])), nil
}

// Create builds a backup envelope from a config document. With
// an empty passphrase the envelope is redacted; with a
// passphrase the secrets are encrypted into the envelope and
// the document stays redacted.
func Create(configDoc []byte, passphrase string) ([]byte, error) {
	redacted, err := RedactDocument(configDoc)
	if err != nil {
		return nil, fmt.Errorf("config is not valid JSON: %w", err)
	}
	env := Envelope{
		Format:  Format,
		Version: Version,
		Created: time.Now().UTC(),
		Secrets: SecretsRedacted,
		Config:  redacted,
	}
	if passphrase != "" {
		if len(passphrase) < MinPassphraseLength {
			return nil, fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLength)
		}
		secrets, err := collectSecrets(configDoc)
		if err != nil {
			return nil, err
		}
		plaintext, err := json.Marshal(secrets)
		if err != nil {
			return nil, err
		}
		binding, err := configBinding(redacted)
		if err != nil {
			return nil, err
		}
		enc, err := EncryptSecrets(plaintext, passphrase, binding)
		if err != nil {
			return nil, err
		}
		env.Secrets = SecretsEncrypted
		env.Encrypted = enc
	}
	return json.MarshalIndent(env, "", "  ")
}

// PrepareRestore resolves a backup envelope into the config
// document to apply. currentDoc is the target instance's live
// config document (for filling redacted placeholders); it may
// be nil when the envelope is encrypted. The returned bytes
// are the full document; callers must still validate it
// (ValidateConfig) before writing or reloading anything. A
// nil currentDoc with a redacted envelope fails: there is
// nothing to fill placeholders from.
func PrepareRestore(envelopeBytes, currentDoc []byte, passphrase string) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("backup is not valid JSON: %w", err)
	}
	if env.Format != Format {
		return nil, errors.New("not a SonuShield backup (bad format marker)")
	}
	if env.Version != Version {
		return nil, fmt.Errorf("unsupported backup version %d (want %d)", env.Version, Version)
	}
	if len(env.Config) == 0 {
		return nil, errors.New("backup has no config document")
	}
	backup, err := parseDoc(env.Config)
	if err != nil {
		return nil, fmt.Errorf("backup config is not valid JSON: %w", err)
	}
	switch env.Secrets {
	case SecretsRedacted:
		if env.Encrypted != nil {
			return nil, errors.New("backup claims redacted secrets but carries an encrypted blob")
		}
		if len(currentDoc) == 0 {
			return nil, errors.New("redacted backup needs the current config to fill secrets from (use an encrypted backup on a fresh instance)")
		}
		current, err := parseDoc(currentDoc)
		if err != nil {
			return nil, fmt.Errorf("current config is not valid JSON: %w", err)
		}
		if err := fillPlaceholders(backup, current); err != nil {
			return nil, err
		}
	case SecretsEncrypted:
		if env.Encrypted == nil {
			return nil, errors.New("backup claims encrypted secrets but carries no encrypted blob")
		}
		if passphrase == "" {
			return nil, errors.New("this backup's secrets are encrypted: a passphrase is required")
		}
		plaintext, err := func() ([]byte, error) {
			binding, err := configBinding(env.Config)
			if err != nil {
				return nil, err
			}
			return DecryptSecrets(env.Encrypted, passphrase, binding)
		}()
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt backup secrets: %w", err)
		}
		var secrets map[string]interface{}
		dec := json.NewDecoder(bytes.NewReader(plaintext))
		dec.UseNumber()
		if err := dec.Decode(&secrets); err != nil {
			return nil, errors.New("decrypted secrets are not valid JSON")
		}
		mergeSecrets(backup, secrets)
	default:
		return nil, fmt.Errorf("unknown backup secrets mode %q", env.Secrets)
	}
	// A resolved document must never still contain a
	// placeholder at a secret path: that would write a
	// placeholder into the live config as a real secret.
	leftover := ""
	walkSecretPaths(backup, func(parent map[string]interface{}, key string, mapLeaf bool) {
		if leftover != "" {
			return
		}
		if mapLeaf {
			if hasPlaceholderKey(parent[key]) {
				leftover = key
			}
			return
		}
		if s, ok := parent[key].(string); ok && s == Placeholder {
			leftover = key
		}
	})
	if leftover != "" {
		return nil, fmt.Errorf("backup still redacts %s after secret resolution; refusing to apply", leftover)
	}
	return encodeDoc(backup)
}
