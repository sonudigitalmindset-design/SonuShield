package api

// Attack timeline + postmortem API (Batch 7).
//
// GET_POSTMORTEM returns an auto-generated postmortem for a
// domain's most recent finished attack (which=last, the
// default) or the attack currently in progress
// (which=current). The report is built ONLY from data the
// proxy already collects: the attack timeline (start/end,
// stage changes, peaks), the current attack-report tallies,
// and the latency window. It adds no new collection.
//
// Parameters:
//   - which: "last" (default) or "current".
//   - format: "json" (default) or "text". Text returns a
//     readable multi-line report in the REPORT_TEXT field.
//   - top: 1..50, how many top sources to list (default 10).
//
// Top sources come from the proxy-wide tallies and are
// labelled as such: they reflect current traffic, not only
// the attack window, because the tallies are not
// per-attack. When no attack has been recorded yet, the
// response reports NONE_FOUND with an empty timeline.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"sonushield/core/domains"
	"sonushield/core/latency"
	"sonushield/core/metrics"
	"sonushield/core/reports"
	"sonushield/core/timeline"
)

// postmortemResponse builds the GET_POSTMORTEM response.
func postmortemResponse(domain string, domainData *domains.DomainData, params map[string]string) (map[string]interface{}, string) {
	which := "last"
	format := "json"
	top := reports.DefaultTop
	for key, value := range params {
		switch key {
		case "which":
			cleaned := strings.ToLower(strings.TrimSpace(value))
			if cleaned != "last" && cleaned != "current" {
				return nil, ERR_INVALID_PARAM
			}
			which = cleaned
		case "format":
			cleaned := strings.ToLower(strings.TrimSpace(value))
			if cleaned != "json" && cleaned != "text" {
				return nil, ERR_INVALID_PARAM
			}
			format = cleaned
		case "top":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 || parsed > reports.MaxTop {
				return nil, ERR_INVALID_PARAM
			}
			top = parsed
		default:
			return nil, ERR_INVALID_PARAM
		}
	}

	var attack timeline.Attack
	var found bool
	if which == "current" {
		attack, found = timeline.Current(domain)
	} else {
		attack, found = timeline.Last(domain)
		if !found {
			// Fall back to the attack in progress, if any,
			// so a first-ever attack still yields a report.
			attack, found = timeline.Current(domain)
		}
	}
	if !found {
		return map[string]interface{}{
			"FOUND":  false,
			"DOMAIN": domain,
			"NOTE":   "no attack has been recorded for this domain yet",
		}, ""
	}

	verified, unverified, fingerprints := reports.CopyTallies()
	report := reports.Build(domain, *domainData, metrics.SnapshotFor(domain), verified, unverified, fingerprints, top)
	latencyStats := latency.StatsFor(domain)

	events := make([]map[string]interface{}, 0, len(attack.Events))
	for _, event := range attack.Events {
		events = append(events, map[string]interface{}{
			"TIME":        event.Time.Format(time.RFC3339),
			"KIND":        event.Kind,
			"DETAIL":      event.Detail,
			"STAGE":       event.Stage,
			"RPS":         event.RPS,
			"RPS_ALLOWED": event.RPSAllowed,
		})
	}

	duration := ""
	if attack.Finished {
		duration = attack.End.Sub(attack.Start).Round(time.Second).String()
	} else {
		duration = time.Since(attack.Start).Round(time.Second).String() + " (ongoing)"
	}

	response := map[string]interface{}{
		"FOUND":                         true,
		"DOMAIN":                        domain,
		"WHICH":                         which,
		"FINISHED":                      attack.Finished,
		"START":                         attack.Start.Format(time.RFC3339),
		"END":                           "",
		"DURATION":                      duration,
		"PEAK_RPS":                      attack.PeakRPS,
		"PEAK_RPS_ALLOWED":              attack.PeakRPSAllowed,
		"MAX_STAGE":                     attack.MaxStage,
		"TIMELINE":                      events,
		"TOP_VERIFIED_IPS_PROXY_WIDE":   report.TopVerifiedIPs,
		"TOP_UNVERIFIED_IPS_PROXY_WIDE": report.TopUnverifiedIPs,
		"TOP_FINGERPRINTS_PROXY_WIDE":   report.TopUnknownFingerprints,
		"COUNTRIES_PROXY_WIDE":          report.Countries,
		"BLOCKS_BY_REASON":              report.BlocksByReason,
		"CHALLENGES_BY_STAGE":           report.ChallengesByStage,
		"LATENCY_TTFB_P95_MS":           latencyMillis(latencyStats.TTFBP95),
		"LATENCY_TOTAL_P95_MS":          latencyMillis(latencyStats.TotalP95),
		"LATENCY_SAMPLES":               latencyStats.Samples,
		"NOTE":                          "Top sources are proxy-wide current tallies, not attack-scoped; the timeline and peaks are attack-scoped.",
	}
	if attack.Finished {
		response["END"] = attack.End.Format(time.RFC3339)
	}
	if format == "text" {
		response["REPORT_FORMAT"] = "text"
		response["REPORT_TEXT"] = postmortemText(domain, attack, duration, report, latencyStats)
	}
	return response, ""
}

// postmortemText renders the readable postmortem. Every figure
// comes from the same inputs as the JSON form.
func postmortemText(domain string, attack timeline.Attack, duration string, report reports.Report, latencyStats latency.Stats) string {
	var b strings.Builder
	status := "ONGOING"
	if attack.Finished {
		status = "FINISHED"
	}
	fmt.Fprintf(&b, "Postmortem: %s (%s)\n", domain, status)
	fmt.Fprintf(&b, "Started: %s\n", attack.Start.Format(time.RFC3339))
	if attack.Finished {
		fmt.Fprintf(&b, "Ended: %s\n", attack.End.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Duration: %s\n", duration)
	fmt.Fprintf(&b, "Peak total RPS: %d\n", attack.PeakRPS)
	fmt.Fprintf(&b, "Peak bypassed RPS: %d\n", attack.PeakRPSAllowed)
	fmt.Fprintf(&b, "Highest stage reached: %d\n", attack.MaxStage)
	b.WriteString("\nTimeline:\n")
	if len(attack.Events) == 0 {
		b.WriteString("  (no events recorded)\n")
	}
	for _, event := range attack.Events {
		fmt.Fprintf(&b, "  %s  [%s] %s (stage %d, %d rps, %d allowed)\n",
			event.Time.Format("15:04:05"), event.Kind, event.Detail, event.Stage, event.RPS, event.RPSAllowed)
	}
	b.WriteString("\nTop sources (proxy-wide current tallies, not attack-scoped):\n")
	for _, entry := range report.TopUnverifiedIPs {
		fmt.Fprintf(&b, "  unverified IP %s: %d requests\n", entry.IP, entry.Requests)
	}
	for _, entry := range report.TopVerifiedIPs {
		fmt.Fprintf(&b, "  verified IP %s: %d requests\n", entry.IP, entry.Requests)
	}
	for _, entry := range report.TopUnknownFingerprints {
		fmt.Fprintf(&b, "  unknown fingerprint %s: %d requests\n", entry.Key, entry.Count)
	}
	b.WriteString("\nOutcome totals (current counters):\n")
	for reason, count := range report.BlocksByReason {
		fmt.Fprintf(&b, "  blocked (%s): %d\n", reason, count)
	}
	for stage, count := range report.ChallengesByStage {
		fmt.Fprintf(&b, "  challenged (stage %s): %d\n", stage, count)
	}
	fmt.Fprintf(&b, "\nOrigin latency over the retained window (%d samples): TTFB p95 %.1f ms, total p95 %.1f ms.\n",
		latencyStats.Samples, latencyMillis(latencyStats.TTFBP95), latencyMillis(latencyStats.TotalP95))
	return b.String()
}
