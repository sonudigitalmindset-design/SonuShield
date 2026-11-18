package firewall

// MatchedRules reports which firewall rules matched a request, for
// structured logging only. It re-applies every compiled filter to
// the same variables EvalFirewallRule used; unlike that function it
// does not stop at a static-set action, so the log lists every
// matching rule, not just the deciding ones. Callers must gate it
// behind logging.Enabled() so the double evaluation only happens
// when JSON logging is active. Rule expressions come from the
// parallel RawCustomRules slice; a missing entry falls back to a
// positional "rule#N" label.

import (
	"sonushield/core/domains"
	"strconv"
	"time"

	"github.com/kor44/gofilter"
)

// scheduleLocation returns the domain's schedule timezone,
// defaulting to UTC when unset (e.g. the debug
// pseudo-domain, which has no configuration).
func scheduleLocation(settings domains.DomainSettings) *time.Location {
	if settings.ScheduleLocation == nil {
		return time.UTC
	}
	return settings.ScheduleLocation
}

func MatchedRules(currDomain domains.DomainSettings, variables gofilter.Message) []string {
	matched := []string{}
	now := time.Now().In(scheduleLocation(currDomain))
	for index, rule := range currDomain.CustomRules {
		if rule.Schedule != nil && !rule.Schedule.ActiveAt(now) {
			continue
		}
		if rule.Filter.Apply(variables) {
			if index < len(currDomain.RawCustomRules) {
				matched = append(matched, currDomain.RawCustomRules[index].Expression)
			} else {
				matched = append(matched, "rule#"+strconv.Itoa(index))
			}
		}
	}
	return matched
}
