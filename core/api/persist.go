package api

// Config-file persistence for dashboard edits.
//
// Rule and domain-config changes made through the API must survive a
// restart, so they are written back to config.json. This file owns
// that write path. The rules are:
//
//   - The file is edited as a generic JSON document, not by
//     re-marshalling the typed Configuration struct, so keys this
//     proxy version does not know about are preserved as data.
//     Only the keys the edit touches are replaced; the whole file
//     is re-indented (2 spaces, keys sorted), which changes
//     formatting but never data.
//   - Writes are atomic: the new content goes to a temporary file in
//     the same directory, the previous config.json is copied to
//     config.json.bak after rotating the backup set (config.json.bak
//     is the newest backup, config.json.bak.1 the one before it,
//     and so on up to the proxy.configBackups limit, default 5),
//     and the temporary file is then renamed over config.json. A
//     failed edit leaves the previous file untouched. Rotation is
//     best-effort: a failed rename never blocks a save.
//   - The whole read-modify-write is serialised by persistMutex, so
//     two concurrent dashboard edits can never lose each other's
//     changes. The mutex is held for file I/O only; applying the
//     change to the running proxy happens after the write succeeds.
//   - The in-memory domains.Config copy is updated on a best-effort
//     basis after a successful write so it does not disagree with the
//     file. The file is the source of truth: a reload or restart
//     re-reads it.
//
// The config path is the same relative "config.json" Load() and
// ReloadConfig() use, so the dashboard edits exactly the file the
// proxy reads. configFilePath is a variable only so tests can point
// it at a scratch directory.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sonushield/core/domains"
	"sync"
)

var (
	configFilePath = "config.json"
	persistMutex   sync.Mutex
)

const (
	defaultBackupLimit = 5
	maxBackupLimit     = 20
)

// backupLimit returns the number of rotating config backups to
// keep, from proxy.configBackups (default 5, clamped to 1-20).
func backupLimit() int {
	limit := defaultBackupLimit
	if domains.Config != nil && domains.Config.Proxy.ConfigBackups != 0 {
		limit = domains.Config.Proxy.ConfigBackups
	}
	if limit < 1 {
		limit = 1
	}
	if limit > maxBackupLimit {
		limit = maxBackupLimit
	}
	return limit
}

// backupPath returns the file path of backup index i: index 0 is
// config.json.bak (newest), index 1 is config.json.bak.1, and so
// on. Paths derive from configFilePath so tests can redirect them.
func backupPath(index int) string {
	if index <= 0 {
		return configFilePath + ".bak"
	}
	return fmt.Sprintf("%s.bak.%d", configFilePath, index)
}

// rotateBackups shifts the backup set one generation older, so
// index 0 becomes free for the backup about to be written.
// Rotation is best-effort: failures are ignored, and backups
// beyond the configured limit are pruned.
func rotateBackups() {
	limit := backupLimit()
	for i := limit - 2; i >= 0; i-- {
		_ = os.Rename(backupPath(i), backupPath(i+1))
	}
	for i := limit; i <= maxBackupLimit; i++ {
		_ = os.Remove(backupPath(i))
	}
}

// writeConfigBytesAtomic writes data to config.json via a
// temporary file in the same directory, renamed over the target.
func writeConfigBytesAtomic(data []byte) error {
	dir := filepath.Dir(configFilePath)
	tmp, err := os.CreateTemp(dir, ".config.json.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, configFilePath)
}

var errDomainNotInConfig = errors.New("domain not found in config.json")

// loadConfigDocument reads config.json as a generic JSON object. The
// values stay raw so untouched keys survive a round-trip unchanged.
func loadConfigDocument() (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("config.json is not valid JSON: %w", err)
	}
	if doc == nil {
		return nil, errors.New("config.json is empty")
	}
	return doc, nil
}

// saveConfigDocument writes doc to config.json atomically, rotating
// the backup set and keeping the previous file as the newest
// backup. The document is written indented for readability; key
// order becomes alphabetical (Go map marshalling), which changes
// formatting but never data.
func saveConfigDocument(doc map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Back up the previous file before replacing it. A missing
	// previous file (fresh install mid-edit) is not an error.
	if previous, err := os.ReadFile(configFilePath); err == nil {
		rotateBackups()
		if err := os.WriteFile(backupPath(0), previous, 0644); err != nil {
			return fmt.Errorf("could not write config backup: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return writeConfigBytesAtomic(data)
}

// updateConfigDomain loads config.json, lets mutate edit one domain
// object, and persists the result. If the domain is missing or mutate
// fails, nothing is written. The domain object is a raw-message map:
// mutate replaces only the keys it owns, every other key (including
// secrets and unknown keys) is preserved untouched.
func updateConfigDomain(domainName string, mutate func(domain map[string]json.RawMessage) error) error {
	persistMutex.Lock()
	defer persistMutex.Unlock()

	doc, err := loadConfigDocument()
	if err != nil {
		return err
	}

	rawDomains, ok := doc["domains"]
	if !ok {
		return errors.New("config.json has no domains list")
	}
	var domainList []json.RawMessage
	if err := json.Unmarshal(rawDomains, &domainList); err != nil {
		return fmt.Errorf("config.json domains list is not valid: %w", err)
	}

	index := -1
	for i, raw := range domainList {
		var probe struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return fmt.Errorf("config.json domain %d is not valid: %w", i, err)
		}
		if probe.Name == domainName {
			index = i
			break
		}
	}
	if index == -1 {
		return errDomainNotInConfig
	}

	var domainObj map[string]json.RawMessage
	if err := json.Unmarshal(domainList[index], &domainObj); err != nil {
		return fmt.Errorf("config.json domain %q is not valid: %w", domainName, err)
	}
	if domainObj == nil {
		domainObj = map[string]json.RawMessage{}
	}

	if err := mutate(domainObj); err != nil {
		return err
	}

	updated, err := json.Marshal(domainObj)
	if err != nil {
		return err
	}
	domainList[index] = updated

	rebuilt, err := json.Marshal(domainList)
	if err != nil {
		return err
	}
	doc["domains"] = rebuilt

	return saveConfigDocument(doc)
}

// updateConfigProxy loads config.json, lets mutate edit the
// "proxy" object as raw JSON, and saves the document
// atomically. It mirrors updateConfigDomain for proxy-level
// keys (e.g. the rule-pack registry) that have no struct
// field. Unknown keys elsewhere in the document survive,
// because the file is edited as generic JSON.
func updateConfigProxy(mutate func(proxy map[string]json.RawMessage) error) error {
	persistMutex.Lock()
	defer persistMutex.Unlock()

	doc, err := loadConfigDocument()
	if err != nil {
		return err
	}

	rawProxy, ok := doc["proxy"]
	if !ok {
		return errors.New("config.json has no proxy object")
	}
	var proxyObj map[string]json.RawMessage
	if err := json.Unmarshal(rawProxy, &proxyObj); err != nil {
		return fmt.Errorf("config.json proxy object is not valid: %w", err)
	}
	if proxyObj == nil {
		proxyObj = map[string]json.RawMessage{}
	}

	if err := mutate(proxyObj); err != nil {
		return err
	}

	updated, err := json.Marshal(proxyObj)
	if err != nil {
		return err
	}
	doc["proxy"] = updated

	return saveConfigDocument(doc)
}

// setRawField replaces one key of a raw-message object with the JSON
// encoding of value.
func setRawField(obj map[string]json.RawMessage, key string, value interface{}) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	obj[key] = encoded
	return nil
}

// syncDomainConfigMemory applies the same field changes to the
// in-memory domains.Config copy, so it does not disagree with the
// file until the next reload. Best effort: if the config or the
// domain is not in memory, there is nothing to sync.
func syncDomainConfigMemory(domainName string, apply func(*domains.Domain)) {
	if domains.Config == nil {
		return
	}
	for i := range domains.Config.Domains {
		if domains.Config.Domains[i].Name == domainName {
			apply(&domains.Config.Domains[i])
			return
		}
	}
}
