package domains

// Data-loss-prevention scanning (Batch 8).
//
// A domain can scan outbound response bodies for
// operator-configured secret patterns (regular expressions,
// config-file-only — no patterns are bundled) and either
// redact the matches or block the response. Patterns are the
// operator's own: SonuShield ships none, so nothing matches
// until the operator writes a pattern.
//
// Privacy rule: matched CONTENT is never logged, never
// returned by any API action, and never stored. Log entries
// and status responses carry only pattern names and match
// counts.
//
// Scanning is bounded: only 2xx responses with text-ish
// content types, without a Content-Encoding, up to
// maxScanBytes (default 1 MB, clamped to 64 KiB–8 MB).
// Oversized or encoded bodies pass through unscanned (fail
// open, documented): DLP is a backstop, not a guarantee.
// Redaction replaces each match with "[redacted]" and drops
// ETag/Content-MD5, since the bytes changed. Blocking answers
// a generic 403. DLP deliberately ignores Cache-Control:
// no-transform: redaction is the operator's explicit security
// policy, not an optimization.

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

// DLPPattern is one operator-configured pattern: a name for
// logs and status output, and a RE2 regular expression.
type DLPPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// DLPConfig is the per-domain DLP configuration (domain.dlp).
// Patterns lists the patterns; Action is "redact" (default)
// or "block"; MaxScanBytes caps the scanned body size.
type DLPConfig struct {
	Patterns     []DLPPattern `json:"patterns"`
	Action       string       `json:"action"`
	MaxScanBytes int64        `json:"maxScanBytes"`
}

const (
	defaultDLPMaxScanBytes = 1 << 20
	minDLPMaxScanBytes     = 64 << 10
	maxDLPMaxScanBytes     = 8 << 20
)

// dlpReplacement is the text substituted for each match.
const dlpReplacement = "[redacted]"

type compiledDLPPattern struct {
	name    string
	re      *regexp.Regexp
	matches atomic.Int64
}

// DLPScanner is the compiled pattern set for one domain. A nil
// scanner means DLP is disabled.
type DLPScanner struct {
	patterns   []compiledDLPPattern
	block      bool
	maxBytes   int64
	scanned    atomic.Int64
	redacted   atomic.Int64
	blocked    atomic.Int64
}

// NewDLPScanner compiles a domain's patterns, or returns nil
// when none are configured. An invalid pattern is skipped with
// a warning; when every pattern is invalid the scanner is nil.
func NewDLPScanner(domainName string, cfg DLPConfig) *DLPScanner {
	if len(cfg.Patterns) == 0 {
		return nil
	}
	scanner := &DLPScanner{
		block:    strings.ToLower(strings.TrimSpace(cfg.Action)) == "block",
		maxBytes: cfg.MaxScanBytes,
	}
	if scanner.maxBytes <= 0 {
		scanner.maxBytes = defaultDLPMaxScanBytes
	}
	if scanner.maxBytes < minDLPMaxScanBytes {
		scanner.maxBytes = minDLPMaxScanBytes
	}
	if scanner.maxBytes > maxDLPMaxScanBytes {
		scanner.maxBytes = maxDLPMaxScanBytes
	}
	for _, pattern := range cfg.Patterns {
		if pattern.Name == "" || pattern.Regex == "" {
			fmt.Println("[ ! ] [ ignoring DLP pattern for " + domainName + ": name and regex must both be set ]")
			continue
		}
		compiled, err := regexp.Compile(pattern.Regex)
		if err != nil {
			fmt.Println("[ ! ] [ ignoring invalid DLP pattern \"" + pattern.Name + "\" for " + domainName + ": " + err.Error() + " ]")
			continue
		}
		scanner.patterns = append(scanner.patterns, compiledDLPPattern{name: pattern.Name, re: compiled})
	}
	if len(scanner.patterns) == 0 {
		return nil
	}
	return scanner
}

// BlockMode reports whether matches block the response
// instead of redacting it.
func (s *DLPScanner) BlockMode() bool {
	return s != nil && s.block
}

// MaxBytes reports the scan cap.
func (s *DLPScanner) MaxBytes() int64 {
	if s == nil {
		return 0
	}
	return s.maxBytes
}

// ScanResult is the outcome of scanning one body: the (possibly
// redacted) body, the names of the patterns that matched, and
// the total match count. Matched content is never included.
type ScanResult struct {
	Body    []byte
	Matched []string
	Matches int
}

// Scan redacts all pattern matches in body and reports what
// matched. It does not decide block vs redact: the caller
// applies the action. Counters are updated for every scan.
func (s *DLPScanner) Scan(body []byte) ScanResult {
	if s == nil {
		return ScanResult{Body: body}
	}
	s.scanned.Add(1)
	result := ScanResult{Body: body}
	for i := range s.patterns {
		pattern := &s.patterns[i]
		matches := pattern.re.FindAllIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		pattern.matches.Add(int64(len(matches)))
		result.Matched = append(result.Matched, pattern.name)
		result.Matches += len(matches)
	}
	if result.Matches == 0 {
		return result
	}
	redacted := body
	for i := range s.patterns {
		redacted = s.patterns[i].re.ReplaceAll(redacted, []byte(dlpReplacement))
	}
	result.Body = redacted
	return result
}

// NoteRedacted records a redacted response; NoteBlocked
// records a blocked one.
func (s *DLPScanner) NoteRedacted() {
	if s != nil {
		s.redacted.Add(1)
	}
}

// NoteBlocked records a blocked response.
func (s *DLPScanner) NoteBlocked() {
	if s != nil {
		s.blocked.Add(1)
	}
}

// DLPPatternStatus is one pattern's match count.
type DLPPatternStatus struct {
	Name    string
	Matches int64
}

// Stats reports the scan counters and per-pattern matches.
func (s *DLPScanner) Stats() (scanned, redacted, blocked int64, patterns []DLPPatternStatus) {
	if s == nil {
		return 0, 0, 0, nil
	}
	patterns = make([]DLPPatternStatus, 0, len(s.patterns))
	for i := range s.patterns {
		patterns = append(patterns, DLPPatternStatus{Name: s.patterns[i].name, Matches: s.patterns[i].matches.Load()})
	}
	return s.scanned.Load(), s.redacted.Load(), s.blocked.Load(), patterns
}
