package reports

// Directory export for attack reports (Batch 2).
//
// When the operator sets proxy.reportDirectory, the proxy writes
// one JSON file and one CSV file per finished attack, named
// <domain>_<window start>_<window end>.json/.csv. Export is
// disabled when the directory is empty (the default), so existing
// configs change nothing.
//
// ExportOnAttackEnd is called from checkAttack while the firewall
// write lock is held, so it must not take that lock itself. It
// copies the domain data synchronously (before the caller resets
// the peaks and request logger) and does the rest — tally copy,
// report build, file writes — in a goroutine, which blocks on the
// read lock only until checkAttack releases it. Failures are
// non-fatal: a message is printed and the proxy keeps running.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sonushield/core/domains"
	"sonushield/core/metrics"
	"sonushield/core/pnc"
	"strings"
	"time"
)

// ReportDirectory returns the operator-configured export directory,
// or "" when export is disabled.
func ReportDirectory() string {
	if domains.Config == nil {
		return ""
	}
	return strings.TrimSpace(domains.Config.Proxy.ReportDirectory)
}

// ExportOnAttackEnd snapshots one finished attack for directory
// export. It returns immediately when export is disabled.
func ExportOnAttackEnd(domain string, data domains.DomainData) {
	dir := ReportDirectory()
	if dir == "" {
		return
	}
	snapshot := data
	snapshot.RequestLogger = append([]domains.RequestLog(nil), data.RequestLogger...)
	go func() {
		defer pnc.PanicHndl()
		verified, unverified, fingerprints := CopyTallies()
		report := Build(domain, snapshot, metrics.SnapshotFor(domain), verified, unverified, fingerprints, DefaultTop)
		if err := writeReportFiles(dir, report); err != nil {
			fmt.Println("[ ! ] [ Attack report export failed:", err, "]")
		}
	}()
}

func sanitizeFilePart(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.' || r == '-' || r == '_':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
	}
	cleaned := out.String()
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "domain"
	}
	return cleaned
}

func reportBaseName(report Report) string {
	start := report.GeneratedAt
	if report.WindowStart != nil {
		start = *report.WindowStart
	}
	end := report.GeneratedAt
	if report.WindowEnd != nil {
		end = *report.WindowEnd
	}
	stamp := func(t time.Time) string { return t.UTC().Format("20060102T150405Z") }
	return sanitizeFilePart(report.Domain) + "_" + stamp(start) + "_" + stamp(end)
}

// writeReportFiles creates the directory if needed and writes the
// JSON and CSV forms. When a file with the computed name already
// exists, a numeric suffix is added so no earlier report is ever
// overwritten.
func writeReportFiles(dir string, report Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	jsonBytes = append(jsonBytes, '\n')
	base := reportBaseName(report)
	jsonPath, err := unusedPath(dir, base, ".json")
	if err != nil {
		return err
	}
	csvPath, err := unusedPath(dir, base, ".csv")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(csvPath, []byte(ToCSV(report)), 0o644); err != nil {
		return err
	}
	return nil
}

func unusedPath(dir, base, ext string) (string, error) {
	candidate := filepath.Join(dir, base+ext)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate, nil
	}
	for i := 2; i <= 100; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no free report filename for %s", base)
}
