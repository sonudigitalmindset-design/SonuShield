package firewall

// HoneypotHit reports whether a request path exactly matches one of
// the operator-configured honeypot paths. Matching is exact and
// case-sensitive on the decoded URL path: honeypot paths must be
// decoys that no legitimate visitor ever requests (for example
// "/.env", "/wp-config.php.bak", or "/admin/login.php" on a site
// that has no such route). There is no prefix or pattern matching,
// so a honeypot can never accidentally catch a real route that
// merely shares a prefix. An empty path list never matches.
func HoneypotHit(paths []string, path string) bool {
	for _, p := range paths {
		if p != "" && p == path {
			return true
		}
	}
	return false
}

// HoneypotBump returns the suspicion bump for a honeypot hit: the
// configured value, or 2 when the operator configured paths but no
// (or a non-positive) bump. Callers must only call it when paths are
// configured.
func HoneypotBump(configured int) int {
	if configured <= 0 {
		return 2
	}
	return configured
}
