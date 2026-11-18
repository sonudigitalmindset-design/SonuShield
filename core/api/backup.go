package api

// Backup + migrate API (Batch 6), proxy actions, v2 only.
//
//   - EXPORT_BACKUP (admin): returns a backup envelope for the
//     live config file. Secrets are redacted by default;
//     include_secrets=true encrypts them into the envelope
//     under the passphrase param (see core/backup). The
//     passphrase param is scrubbed from audit logs.
//   - RESTORE_BACKUP (admin): applies a backup envelope.
//     The envelope is fully resolved (secrets merged or
//     decrypted) and validated BEFORE anything is written;
//     a bad backup changes nothing. On reload failure the
//     previous file is restored and reloaded, following the
//     same discipline as the domain import.
//
// Both actions are admin-only and forbidden to tenant-scoped
// callers (central tenant check). Backup envelopes are capped
// at 1 MB, like rule imports.

import (
	"encoding/json"
	"os"

	"sonushield/core/backup"
	"sonushield/core/domains"
)

const maxBackupSize = 1 << 20 // 1 MB

func exportBackupResponse(params map[string]string) (map[string]interface{}, string, string) {
	includeSecrets := false
	passphrase := ""
	for key, value := range params {
		switch key {
		case "include_secrets":
			if value == "true" {
				includeSecrets = true
			} else if value != "false" {
				return nil, ERR_INVALID_PARAM, "include_secrets must be true or false"
			}
		case "passphrase":
			passphrase = value
		default:
			return nil, ERR_INVALID_PARAM, "unknown parameter " + key
		}
	}
	if includeSecrets && passphrase == "" {
		return nil, ERR_INVALID_PARAM, "passphrase is required when include_secrets is true"
	}
	if !includeSecrets {
		passphrase = ""
	}
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	envelope, err := backup.Create(data, passphrase)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	return map[string]interface{}{
		"BACKUP": json.RawMessage(envelope),
	}, "", ""
}

func restoreEnvelopeResponse(params map[string]string) (map[string]interface{}, string, string) {
	if ConfigValidator == nil || ConfigReloader == nil {
		return nil, ERR_ACTION_NOT_FOUND, ""
	}
	raw := ""
	passphrase := ""
	for key, value := range params {
		switch key {
		case "backup":
			raw = value
		case "passphrase":
			passphrase = value
		default:
			return nil, ERR_INVALID_PARAM, "unknown parameter " + key
		}
	}
	if raw == "" {
		return nil, ERR_INVALID_PARAM, "backup parameter is required"
	}
	if len(raw) > maxBackupSize {
		return nil, ERR_INVALID_PARAM, "backup exceeds 1 MB"
	}

	persistMutex.Lock()
	defer persistMutex.Unlock()

	previous, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	var header struct {
		Secrets string `json:"secrets"`
	}
	_ = json.Unmarshal([]byte(raw), &header)
	resolved, err := backup.PrepareRestore([]byte(raw), previous, passphrase)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(resolved, &cfg); err != nil {
		return nil, ERR_INVALID_PARAM, "restored config is not valid: " + err.Error()
	}
	if err := ConfigValidator(&cfg); err != nil {
		return nil, ERR_INVALID_PARAM, "restored config failed validation: " + err.Error()
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(resolved, &doc); err != nil {
		return nil, ERR_INVALID_PARAM, "restored config is not valid: " + err.Error()
	}
	if err := saveConfigDocument(doc); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	if err := ConfigReloader(); err != nil {
		// Roll the file swap back, then reload best-effort
		// so the running proxy matches the file again.
		_ = writeConfigBytesAtomic(previous)
		_ = ConfigReloader()
		return nil, ERR_RELOAD_FAILED, err.Error()
	}
	mode := header.Secrets
	if mode == "" {
		mode = backup.SecretsRedacted
	}
	return map[string]interface{}{
		"RESTORED":     true,
		"DOMAINS":      len(cfg.Domains),
		"SECRETS_MODE": mode,
		"RELOADED":     true,
	}, "", ""
}
