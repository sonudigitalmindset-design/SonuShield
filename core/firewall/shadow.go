package firewall

// Shadow mode (Batch 7).
//
// Shadow mode runs a SEPARATE rule set (and optionally the
// WAF-lite patterns) against every request, in parallel with
// live enforcement, and records what WOULD have happened —
// without ever affecting traffic. It answers the operator's
// question "what would these new rules do to my real traffic?"
// before the rules go live. It is distinct from dry-run mode
// (Batch 4), which disables enforcement of the LIVE rules;
// shadow mode leaves live enforcement untouched and evaluates
// an additional, independent rule set.
//
// The shadow rules start from the same pre-rule suspicion
// level the live rules started from, so the comparison is
// apples-to-apples. Outcomes are mapped from the resulting
// level exactly like the challenge switch: above 3 is "block",
// 1-3 is "challenge", 0 or below is "allow".
//
// Shadow WAF covers the pattern rules only, via the
// side-effect-free MatchWAFPatterns: the WordPress login
// flood counter is deliberately NOT consulted, because
// counting a request twice (live + shadow) would corrupt the
// live counter.
//
// Decisions are aggregated per domain (counts, per-rule match
// tallies, and the 50 most recent decisions) and exposed via
// the GET_SHADOW_REPORT API action. Shadow matches are also
// written to the structured log as "shadow" entries when
// logging is enabled, like dry-run entries. With no shadow
// rules and shadowWaf off, nothing is evaluated and nothing
// is recorded.

import (
	"strconv"
	"sync"
	"time"

	"sonushield/core/domains"

	"github.com/kor44/gofilter"
)

// CompileShadowRules compiles operator shadow rules. Unlike
// the live rules, a bad expression or action never panics:
// the rule is skipped with a warning, because a shadow
// experiment must never break startup or reload. The returned
// raw slice parallels the compiled slice (skipped rules are
// absent from both), so matched-rule labels stay aligned.
func CompileShadowRules(raw []domains.JsonRule) (compiled []domains.Rule, kept []domains.JsonRule, warnings []string) {
	compiled = []domains.Rule{}
	kept = []domains.JsonRule{}
	for index, rawRule := range raw {
		filter, err := gofilter.NewFilter(rawRule.Expression)
		if err != nil {
			warnings = append(warnings, "shadow rule "+strconv.Itoa(index)+" skipped: expression does not compile: "+err.Error())
			continue
		}
		if !domains.ValidRuleAction(rawRule.Action) {
			warnings = append(warnings, "shadow rule "+strconv.Itoa(index)+" skipped: invalid action "+strconv.Quote(rawRule.Action))
			continue
		}
		compiled = append(compiled, domains.Rule{Filter: filter, Action: rawRule.Action})
		kept = append(kept, rawRule)
	}
	return compiled, kept, warnings
}

// ShadowOutcome maps a suspicion level to the outcome label
// the challenge switch would produce for it.
func ShadowOutcome(susLv int) string {
	switch {
	case susLv > 3:
		return "block"
	case susLv > 0:
		return "challenge"
	default:
		return "allow"
	}
}

// EvalShadowRules applies the compiled shadow rules to one
// request's variables, starting from susLv, and returns the
// resulting level plus the expressions of every rule that
// matched. It shares applyRuleAction with the live evaluator
// so actions behave identically; unlike EvalFirewallRule it
// reports all matches, not just the deciding ones.
func EvalShadowRules(rules []domains.Rule, raw []domains.JsonRule, variables gofilter.Message, susLv int) (int, []string) {
	result := susLv
	matched := []string{}
	for index, rule := range rules {
		if !rule.Filter.Apply(variables) {
			continue
		}
		if index < len(raw) {
			matched = append(matched, raw[index].Expression)
		} else {
			matched = append(matched, "rule#"+strconv.Itoa(index))
		}
		var stop bool
		result, stop = applyRuleAction(rule.Action, index, result)
		if stop {
			return result, matched
		}
	}
	return result, matched
}

// ShadowDecision is one request's shadow-vs-live comparison.
type ShadowDecision struct {
	Time          time.Time
	IP            string
	Method        string
	Path          string
	LiveOutcome   string
	ShadowOutcome string
	LiveSusLv     int
	ShadowSusLv   int
	Matched       []string
	WAFRule       string
}

// ShadowStats is the aggregated per-domain shadow report.
type ShadowStats struct {
	Evaluated      int64
	WouldBlock     int64
	WouldChallenge int64
	WouldAllow     int64
	Disagreements  int64
	RuleMatches    map[string]int64
	Recent         []ShadowDecision
}

const shadowRecentMax = 50

type shadowDomainStats struct {
	evaluated      int64
	wouldBlock     int64
	wouldChallenge int64
	wouldAllow     int64
	disagreements  int64
	ruleMatches    map[string]int64
	recent         []ShadowDecision
}

var (
	shadowMu    sync.Mutex
	shadowStats = map[string]*shadowDomainStats{}
)

// RecordShadowDecision aggregates one comparison for a domain.
// A zero Time is stamped with the current time.
func RecordShadowDecision(domain string, decision ShadowDecision) {
	if domain == "" {
		return
	}
	if decision.Time.IsZero() {
		decision.Time = time.Now()
	}
	shadowMu.Lock()
	defer shadowMu.Unlock()
	stats, ok := shadowStats[domain]
	if !ok {
		stats = &shadowDomainStats{ruleMatches: map[string]int64{}}
		shadowStats[domain] = stats
	}
	stats.evaluated++
	switch decision.ShadowOutcome {
	case "block":
		stats.wouldBlock++
	case "challenge":
		stats.wouldChallenge++
	default:
		stats.wouldAllow++
	}
	if decision.ShadowOutcome != decision.LiveOutcome {
		stats.disagreements++
	}
	for _, expr := range decision.Matched {
		stats.ruleMatches[expr]++
	}
	if decision.WAFRule != "" {
		stats.ruleMatches["waf:"+decision.WAFRule]++
	}
	stats.recent = append(stats.recent, decision)
	if len(stats.recent) > shadowRecentMax {
		stats.recent = stats.recent[len(stats.recent)-shadowRecentMax:]
	}
}

// ShadowReport returns a copy of the aggregated shadow stats
// for a domain. Missing domains yield an empty report.
func ShadowReport(domain string) ShadowStats {
	shadowMu.Lock()
	defer shadowMu.Unlock()
	report := ShadowStats{RuleMatches: map[string]int64{}, Recent: []ShadowDecision{}}
	stats, ok := shadowStats[domain]
	if !ok {
		return report
	}
	report.Evaluated = stats.evaluated
	report.WouldBlock = stats.wouldBlock
	report.WouldChallenge = stats.wouldChallenge
	report.WouldAllow = stats.wouldAllow
	report.Disagreements = stats.disagreements
	for expr, count := range stats.ruleMatches {
		report.RuleMatches[expr] = count
	}
	report.Recent = append(report.Recent, stats.recent...)
	return report
}
