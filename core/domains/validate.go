package domains

// Shared validation helpers for values that appear both in the
// config file and in API requests.

import "regexp"

var ruleActionPattern = regexp.MustCompile(`^[+-]?[0-9]+$`)

// ValidRuleAction reports whether a firewall rule action is spelled
// the way the evaluator expects: a plain integer (static suspicion
// level) or +N / -N (adjust the level and keep evaluating). Anything
// else would fail or crash request evaluation, which indexes the
// action's first byte and scans the rest as an integer.
func ValidRuleAction(action string) bool {
	return ruleActionPattern.MatchString(action)
}
