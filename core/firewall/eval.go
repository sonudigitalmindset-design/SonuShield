package firewall

import (
	"fmt"
	"sonushield/core/domains"
	"time"

	"github.com/kor44/gofilter"
)

func EvalFirewallRule(currDomain domains.DomainSettings, variables gofilter.Message, susLv int) int {
	result := susLv
	//Scheduled rules (Batch 7): a rule whose schedule does
	//not match the current time in the domain's timezone is
	//skipped entirely, as if it were not configured.
	now := time.Now().In(scheduleLocation(currDomain))
	for index, rule := range currDomain.CustomRules {
		if rule.Schedule != nil && !rule.Schedule.ActiveAt(now) {
			continue
		}
		if rule.Filter.Apply(variables) {
			var stop bool
			result, stop = applyRuleAction(rule.Action, index, result)
			if stop {
				return result
			}
		}
	}
	return result
}

// applyRuleAction applies one matched rule's action to the
// suspicion level, returning the new level and whether evaluation
// must stop. A plain integer sets the level and stops; +N/-N
// adjust the level and evaluation continues. A malformed action
// is logged and leaves the level unchanged (evaluation
// continues). Shared by EvalFirewallRule and the edge rules
// engine (EvalEdgeRules) so both apply actions identically.
func applyRuleAction(action string, index, result int) (int, bool) {
	//Check if we want to statically set susLv or add to it
	switch action[:1] {
	case "+":
		var actionInt int
		_, err := fmt.Sscan(action[1:], &actionInt)
		if err != nil {
			fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
			//Dont change anything on error. We dont want issues in production
		} else {
			result = result + actionInt
		}
	case "-":
		var actionInt int
		_, err := fmt.Sscan(action[1:], &actionInt)
		if err != nil {
			fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
			//Dont change anything on error. We dont want issues in production
		} else {
			result = result - actionInt
		}
	default:
		var actionInt int
		_, err := fmt.Sscan(action, &actionInt)
		if err != nil {
			fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
		} else {
			result = actionInt
			return result, true
		}
	}
	return result, false
}
