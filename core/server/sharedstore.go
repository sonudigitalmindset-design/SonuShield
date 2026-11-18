package server

import (
	"fmt"
	"time"

	"sonushield/core/domains"
	"sonushield/core/proxy"
	"sonushield/core/shared"
)

// applySharedStoreConfig (re)configures the process-wide
// Redis-backed shared store (Batch 3) from the live
// configuration. It runs once at startup (from Serve) and
// after every validated reload (from reloadFromConfig), so
// enabling, disabling, or repointing Redis takes effect
// without a restart.
//
//   - Redis disabled (the default): any running store is shut
//     down and the proxy uses local state only.
//   - Redis enabled but unreachable: the previous store, if
//     any, keeps running and one generic line is logged. The
//     proxy never fails to start or reload because of Redis.
//   - The Redis password is passed only to the client
//     constructor; it is never logged.
//
// SafeReload validates the config before applying it, so a
// reload that reaches here has a non-empty address when
// Redis is enabled.
func applySharedStoreConfig() {
	if domains.Config == nil || !domains.Config.Proxy.Redis.Enabled {
		shared.Shutdown()
		return
	}
	rc := domains.Config.Proxy.Redis
	err := shared.Configure(shared.Options{
		Addr:          rc.Addr,
		Password:      rc.Password,
		DB:            rc.DB,
		TLS:           rc.TLS,
		KeyPrefix:     rc.KeyPrefix,
		WindowSeconds: proxy.RatelimitWindow,
		SharedCache:   rc.SharedCache,
		Timeout:       time.Duration(rc.TimeoutMs) * time.Millisecond,
	})
	if err != nil {
		fmt.Println("[ ! ] [ Shared store unavailable, using local state ]")
	}
}
