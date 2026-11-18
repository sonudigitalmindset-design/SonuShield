package api

// Log search and attack map (Batch 5).
//
//   - SEARCH_LOGS (proxy or domain, viewer): search the structured
//     JSON log files (current + rotated, newest first). Filters:
//     domain (proxy action only), ip, action, event, from/to
//     (unix seconds). Results are paginated (page, perPage up to
//     200) and bounded: at most maxSearchLines lines are scanned
//     and at most maxSearchMatches matches are kept, so a huge
//     log can never exhaust memory; TRUNCATED reports when either
//     bound was hit. Requires JSON logging configured
//     (proxy.logFormat "json" + proxy.logFile), otherwise
//     ERR_JSON_LOGS_NOT_CONFIGURED.
//   - GET_ATTACK_MAP (proxy, viewer): top countries by blocked /
//     challenged requests in a recent window, aggregated from the
//     country field the logger resolves at write time. Country
//     data exists only when the operator configured a GeoIP
//     database: without one the response is empty with
//     GEO_CONFIGURED false. Without JSON logging the response is
//     empty with LOGS_CONFIGURED false (not an error — the map is
//     an overview, and the dashboard shows setup guidance).
//
// Scans are best-effort snapshots: a rotation mid-scan may rarely
// miss or repeat a line, and unparseable lines are skipped.

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/privacy"
	"strconv"
	"strings"
	"time"
)

const (
	maxSearchLines   = 200000
	maxSearchMatches = 5000
	maxSearchPerPage = 200
	defaultPerPage   = 50
)

// logFilter selects structured-log entries. Empty strings and zero
// times mean "no constraint" for that field.
type logFilter struct {
	domain string
	ip     string
	action string
	event  string
	from   int64
	to     int64
}

func (f logFilter) matches(entry logging.Entry) bool {
	if f.domain != "" && entry.Domain != f.domain {
		return false
	}
	if f.ip != "" && entry.IP != f.ip {
		return false
	}
	if f.action != "" && entry.Action != f.action {
		return false
	}
	if f.event != "" && entry.Event != f.event {
		return false
	}
	if f.from != 0 && entry.Timestamp.Unix() < f.from {
		return false
	}
	if f.to != 0 && entry.Timestamp.Unix() > f.to {
		return false
	}
	return true
}

// scanLogEntries walks the log files newest-first and calls visit
// for each matching entry, in newest-first order. Scanning stops
// early when visit returns false. It reports the lines scanned
// and whether the line cap truncated the scan.
func scanLogEntries(files []string, filter logFilter, visit func(logging.Entry) bool) (scanned int, truncated bool) {
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		matches := scanOneLogFile(file, filter, &scanned, &truncated)
		file.Close()
		// Within a file lines are oldest-first; reverse so the
		// caller sees newest-first across the whole scan.
		for i := len(matches) - 1; i >= 0; i-- {
			if !visit(matches[i]) {
				return scanned, truncated
			}
		}
		if truncated {
			return scanned, truncated
		}
	}
	return scanned, truncated
}

// scanOneLogFile parses one log file and returns its matching
// entries in file order. scanned/truncated are shared with the
// caller so the line cap spans all files.
func scanOneLogFile(file *os.File, filter logFilter, scanned *int, truncated *bool) []logging.Entry {
	var matches []logging.Entry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		*scanned++
		if *scanned > maxSearchLines {
			*truncated = true
			return matches
		}
		var entry logging.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if filter.matches(entry) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// parseSearchParams validates the shared SEARCH_LOGS parameters.
// domainScope, when non-empty, forces the domain filter (domain
// action); the proxy action accepts a "domain" param instead.
func parseSearchParams(domainScope string, params map[string]string) (logFilter, int, int, string) {
	filter := logFilter{domain: domainScope}
	page, perPage := 1, defaultPerPage
	for key, value := range params {
		switch key {
		case "domain":
			if domainScope != "" {
				return filter, 0, 0, ERR_INVALID_PARAM
			}
			filter.domain = value
		case "ip":
			filter.ip = value
		case "action":
			filter.action = value
		case "event":
			filter.event = value
		case "from", "to":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || parsed < 0 {
				return filter, 0, 0, ERR_INVALID_PARAM
			}
			if key == "from" {
				filter.from = parsed
			} else {
				filter.to = parsed
			}
		case "page":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || parsed < 1 {
				return filter, 0, 0, ERR_INVALID_PARAM
			}
			page = parsed
		case "perPage":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || parsed < 1 || parsed > maxSearchPerPage {
				return filter, 0, 0, ERR_INVALID_PARAM
			}
			perPage = parsed
		default:
			return filter, 0, 0, ERR_INVALID_PARAM
		}
	}
	if filter.from != 0 && filter.to != 0 && filter.from > filter.to {
		return filter, 0, 0, ERR_INVALID_PARAM
	}
	return filter, page, perPage, ""
}

// searchLogsResponse runs one SEARCH_LOGS query.
func searchLogsResponse(domainScope string, params map[string]string) (map[string]interface{}, string) {
	files := logging.LogFiles()
	if files == nil {
		return nil, ERR_JSON_LOGS_NOT_CONFIGURED
	}
	filter, page, perPage, errCode := parseSearchParams(domainScope, params)
	if errCode != "" {
		return nil, errCode
	}

	var kept []logging.Entry
	total := 0
	capped := false
	scanned, truncated := scanLogEntries(files, filter, func(entry logging.Entry) bool {
		total++
		// Privacy mode (Batch 7): entries written before
		// privacy mode was enabled still hold raw IPs and
		// user-agents on disk; mask them on the way out.
		// The ip filter above matches stored values.
		if privacy.Enabled() {
			entry.IP = privacy.MaskIP(entry.IP)
			entry.UserAgent = ""
		}
		if len(kept) < maxSearchMatches {
			kept = append(kept, entry)
		} else {
			capped = true
		}
		return true
	})

	start := (page - 1) * perPage
	var pageEntries []logging.Entry
	if start < len(kept) {
		end := start + perPage
		if end > len(kept) {
			end = len(kept)
		}
		pageEntries = kept[start:end]
	} else {
		pageEntries = []logging.Entry{}
	}

	return map[string]interface{}{
		"ENTRIES":      pageEntries,
		"TOTAL":        total,
		"PAGE":         page,
		"PER_PAGE":     perPage,
		"SCANNED":      scanned,
		"FILES":        len(files),
		"TRUNCATED":    truncated || capped,
		"LOGS_CONFIGURED": true,
	}, ""
}

// attackMapResponse runs one GET_ATTACK_MAP query.
func attackMapResponse(params map[string]string) map[string]interface{} {
	top := 10
	windowSeconds := int64(3600)
	for key, value := range params {
		switch key {
		case "top":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil && parsed >= 1 && parsed <= 50 {
				top = parsed
			}
		case "window":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err == nil && parsed >= 60 && parsed <= 86400 {
				windowSeconds = parsed
			}
		}
	}
	// Unknown params are ignored here (unlike SEARCH_LOGS): the
	// map is a best-effort overview, not a precise query.

	empty := func(logsConfigured bool) map[string]interface{} {
		return map[string]interface{}{
			"COUNTRIES":       []map[string]interface{}{},
			"GEO_CONFIGURED":  firewall.GeoConfigured(),
			"LOGS_CONFIGURED": logsConfigured,
			"SCANNED":         0,
			"TRUNCATED":       false,
		}
	}
	if !firewall.GeoConfigured() {
		return empty(logging.LogFiles() != nil)
	}
	files := logging.LogFiles()
	if files == nil {
		return empty(false)
	}

	type countryTally struct {
		blocks     int
		challenges int
	}
	tallies := map[string]*countryTally{}
	filter := logFilter{from: time.Now().Unix() - windowSeconds}
	scanned, truncated := scanLogEntries(files, filter, func(entry logging.Entry) bool {
		if entry.Country == "" {
			return true
		}
		tally, ok := tallies[entry.Country]
		if !ok {
			tally = &countryTally{}
			tallies[entry.Country] = tally
		}
		switch entry.Event {
		case "block":
			tally.blocks++
		case "challenge":
			tally.challenges++
		}
		return true
	})

	countries := make([]map[string]interface{}, 0, len(tallies))
	for country, tally := range tallies {
		total := tally.blocks + tally.challenges
		if total == 0 {
			continue
		}
		countries = append(countries, map[string]interface{}{
			"COUNTRY":    country,
			"BLOCKS":     tally.blocks,
			"CHALLENGES": tally.challenges,
			"TOTAL":      total,
		})
	}
	sort.Slice(countries, func(i, j int) bool {
		return countries[i]["TOTAL"].(int) > countries[j]["TOTAL"].(int)
	})
	if len(countries) > top {
		countries = countries[:top]
	}
	return map[string]interface{}{
		"COUNTRIES":       countries,
		"GEO_CONFIGURED":  true,
		"LOGS_CONFIGURED": true,
		"SCANNED":         scanned,
		"TRUNCATED":       truncated,
	}
}
