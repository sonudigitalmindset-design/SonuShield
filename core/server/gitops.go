package server

// GitOps config-as-code sync (Batch 5).
//
// When proxy.gitops is enabled, a background watcher polls a
// local git-checkout directory for config.json changes and
// applies them through the validated SafeReload path. The sync
// is one-way and opt-in:
//
//   - Disabled by default. Enable with proxy.gitops.enabled and
//     proxy.gitops.directory (the checkout directory; the file
//     watched is <directory>/config.json). The interval
//     (proxy.gitops.intervalSeconds, default 60, minimum 10) is
//     how often the file is checked.
//   - The watcher reads the live proxy settings on every tick,
//     so enabling, disabling, or retargeting GitOps takes effect
//     on the next reload without a restart. (A reload applies
//     the new settings; the watcher itself never restarts.)
//   - A changed file is parsed and validated with ValidateConfig
//     — the same validation the API reload uses — before
//     anything is written. A bad synced config is logged and
//     skipped; it can never take the proxy down, and the running
//     config is untouched.
//   - A valid file is written to ./config.json atomically (temp
//     file + rename, previous file kept as config.json.bak) and
//     applied with SafeReload, which validates again before
//     applying.
//   - Sync is one-way: dashboard edits to ./config.json survive
//     until the next git change, which overwrites them. Do not
//     combine GitOps with dashboard config edits.
//
// The watcher never shells out to git: the operator's own
// checkout tooling (a cron pull, a deployment hook) keeps the
// directory fresh; the proxy only reads the file. Change
// detection is hash-based, so a rewrite with identical content
// never triggers a reload.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sonushield/core/domains"
	"sync"
	"time"
)

const (
	gitopsDefaultInterval = 60 * time.Second
	gitopsMinInterval     = 10 * time.Second
	gitopsPollTick        = 10 * time.Second
)

var gitopsOnce sync.Once

// StartGitOpsWatcher starts the GitOps sync loop exactly once.
// It is called from Serve, after config.Load has run. When
// GitOps is disabled the loop sleeps, re-checking the live
// settings on every tick, so enabling it via a reload starts
// syncing without a restart.
func StartGitOpsWatcher() {
	gitopsOnce.Do(func() { go gitopsLoop() })
}

// gitopsSettings returns the live GitOps settings, or disabled
// when the config is unavailable.
func gitopsSettings() domains.GitOpsConfig {
	if domains.Config == nil {
		return domains.GitOpsConfig{}
	}
	return domains.Config.Proxy.GitOps
}

func gitopsLoop() {
	lastApplied := ""
	if data, err := os.ReadFile("config.json"); err == nil {
		sum := sha256.Sum256(data)
		lastApplied = hex.EncodeToString(sum[:])
	}
	var lastCheck time.Time
	for {
		time.Sleep(gitopsPollTick)
		settings := gitopsSettings()
		if !settings.Enabled || settings.Directory == "" {
			continue
		}
		interval := time.Duration(settings.IntervalSeconds) * time.Second
		if interval < gitopsMinInterval {
			interval = gitopsDefaultInterval
		}
		if time.Since(lastCheck) < interval {
			continue
		}
		lastCheck = time.Now()
		if applied, ok := gitopsSyncOnce(settings.Directory, lastApplied); ok {
			lastApplied = applied
		}
	}
}

// gitopsSyncOnce checks one sync cycle. It returns the hash to
// record as applied (the synced file's hash on success, the
// previous value otherwise) and whether the hash changed.
func gitopsSyncOnce(directory, lastApplied string) (string, bool) {
	syncedPath := filepath.Join(directory, "config.json")
	data, err := os.ReadFile(syncedPath)
	if err != nil {
		fmt.Println("[ ! ] [ gitops: cannot read", syncedPath, ":", err, "]")
		return lastApplied, false
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if hash == lastApplied {
		return lastApplied, false
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Println("[ ! ] [ gitops: synced config is not valid JSON, skipping:", err, "]")
		return lastApplied, false
	}
	if err := ValidateConfig(&cfg); err != nil {
		fmt.Println("[ ! ] [ gitops: synced config failed validation, skipping:", err, "]")
		return lastApplied, false
	}
	if err := gitopsWriteConfig(data); err != nil {
		fmt.Println("[ ! ] [ gitops: cannot write config.json:", err, "]")
		return lastApplied, false
	}
	if err := SafeReload(); err != nil {
		fmt.Println("[ ! ] [ gitops: reload failed after sync:", err, "]")
		return lastApplied, false
	}
	fmt.Println("[ gitops ] [ applied config from", syncedPath, "]")
	return hash, true
}

// gitopsWriteConfig replaces ./config.json atomically, keeping
// the previous file as config.json.bak. It mirrors the dashboard
// write discipline without the backup rotation: GitOps keeps a
// single backup, and the git checkout itself is the history.
func gitopsWriteConfig(data []byte) error {
	if previous, err := os.ReadFile("config.json"); err == nil {
		if err := os.WriteFile("config.json.bak", previous, 0644); err != nil {
			return fmt.Errorf("could not write config backup: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(".", ".config.json.gitops.*")
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
	return os.Rename(tmpName, "config.json")
}
