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

	"github.com/kor44/gofilter"
)

func MatchedRules(currDomain domains.DomainSettings, variables gofilter.Message) []string {
	matched := []string{}
	for index, rule := range currDomain.CustomRules {
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
