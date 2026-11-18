package domains

// GitOps configuration (Batch 5). See core/server/gitops.go for
// the sync semantics. Disabled by default: Enabled false, or an
// empty Directory, means the watcher never syncs.
type GitOpsConfig struct {
	Enabled         bool   `json:"enabled"`
	Directory       string `json:"directory"`
	IntervalSeconds int    `json:"intervalSeconds"`
}
