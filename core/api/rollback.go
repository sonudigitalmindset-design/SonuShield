package api

// Config rollback (Batch 4).
//
// Every config write rotates the backup set, so earlier versions
// of config.json survive as config.json.bak (newest),
// config.json.bak.1, and so on, up to the proxy.configBackups
// limit. LIST_CONFIG_BACKUPS lists them; RESTORE_CONFIG_BACKUP
// validates a chosen backup with the same checks as SafeReload,
// swaps it in atomically (backing up the current file first),
// and reloads. If the reload fails, the previous file is written
// back and reloaded best-effort, so a restore can never leave
// the proxy running a config the file disagrees with.
//
// Backup names are validated strictly: only the exact file names
// in this scheme are accepted, so no path traversal is possible.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sonushield/core/domains"
	"strconv"
	"strings"
	"time"
)

// ConfigValidator, when set, validates a parsed configuration
// with the same checks SafeReload applies before touching the
// running proxy. It is a hook for the same import-cycle reason
// as ConfigReloader; the server package sets it at init time.
// When unset, RESTORE_CONFIG_BACKUP reports the action as
// unavailable instead of restoring an unvalidated config.
var ConfigValidator func(cfg *domains.Configuration) error

// backupNamePattern matches exactly the names this scheme
// produces for the configured file's base name.
func backupNamePattern() *regexp.Regexp {
	base := regexp.QuoteMeta(filepath.Base(configFilePath))
	return regexp.MustCompile(`^` + base + `\.bak(\.(\d+))?$`)
}

// parseBackupName validates a backup name from the API and
// returns its index: 0 for config.json.bak, N for
// config.json.bak.N.
func parseBackupName(name string) (int, bool) {
	matches := backupNamePattern().FindStringSubmatch(name)
	if matches == nil {
		return 0, false
	}
	if matches[2] == "" {
		return 0, true
	}
	index, err := strconv.Atoi(matches[2])
	if err != nil || index > maxBackupLimit {
		return 0, false
	}
	return index, true
}

// listBackupsResponse returns every existing backup, newest
// first, with size and modification time.
func listBackupsResponse() map[string]interface{} {
	persistMutex.Lock()
	defer persistMutex.Unlock()

	backups := []map[string]interface{}{}
	for i := 0; i < maxBackupLimit; i++ {
		info, err := os.Stat(backupPath(i))
		if err != nil {
			continue
		}
		backups = append(backups, map[string]interface{}{
			"NAME":     filepath.Base(backupPath(i)),
			"SIZE":     info.Size(),
			"MODIFIED": info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	return map[string]interface{}{
		"BACKUPS": backups,
	}
}

// restoreBackupResponse validates and restores one backup. The
// swap and reload hold persistMutex for the whole operation, so
// no concurrent dashboard edit can interleave with the restore.
func restoreBackupResponse(params map[string]string) (map[string]interface{}, string, string) {
	name := strings.TrimSpace(params["backup"])
	if name == "" {
		return nil, ERR_PARAMS_REQUIRED, "backup parameter required"
	}
	index, ok := parseBackupName(name)
	if !ok {
		return nil, ERR_INVALID_PARAM, "unknown backup name"
	}
	if ConfigValidator == nil || ConfigReloader == nil {
		return nil, ERR_ACTION_NOT_FOUND, ""
	}

	data, err := os.ReadFile(backupPath(index))
	if err != nil {
		return nil, ERR_INVALID_PARAM, "backup not found"
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, ERR_INVALID_PARAM, "backup is not valid config JSON"
	}
	if err := ConfigValidator(&cfg); err != nil {
		return nil, ERR_INVALID_PARAM, fmt.Sprintf("backup failed validation: %s", err.Error())
	}

	persistMutex.Lock()
	defer persistMutex.Unlock()

	previous, readErr := os.ReadFile(configFilePath)
	previousExists := readErr == nil
	rotateBackups()
	if previousExists {
		if err := os.WriteFile(backupPath(0), previous, 0644); err != nil {
			return nil, ERR_CONFIG_WRITE_FAILED, "could not back up current config"
		}
	}
	if err := writeConfigBytesAtomic(data); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	if err := ConfigReloader(); err != nil {
		// Roll the file swap back, then reload best-effort so
		// the running proxy matches the file again.
		if previousExists {
			_ = writeConfigBytesAtomic(previous)
		} else {
			_ = os.Remove(configFilePath)
		}
		_ = ConfigReloader()
		return nil, ERR_RELOAD_FAILED, err.Error()
	}
	return map[string]interface{}{
		"RESTORED": name,
	}, "", ""
}
