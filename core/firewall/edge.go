package firewall

// Edge rules engine (Batch 6): a fast-path precompiled rule chain
// evaluated before the general firewall rules.
//
// An edge rule is a single comparison — one field, one operator,
// one literal — compiled once at load time into a direct check,
// with no interpreter and no allocation per request. The chain
// runs first and behaves exactly as if its rules were prepended
// to the general rule list: +N/-N actions adjust the suspicion
// level and evaluation continues into the general rules, while a
// plain-integer action sets the level and stops all further rule
// evaluation. The intended use is cheap early decisions:
// known-good fingerprints, static allows, and other single-test
// rules that currently pay the gofilter interpreter on every
// request.
//
// Accepted grammar (anything else is rejected at load with a
// warning, and the rule must stay a general firewall rule):
//   - One comparison: `<field> <op> <literal>`, with the word
//     operators eq, ne, gt, ge, lt, le, contains, separated by
//     whitespace. Symbolic operators (==, !=, >, ...), compound
//     expressions (and/or/not, parentheses), and regex matches
//     are not accepted.
//   - Fields: every gofilter-registered field except the boolean
//     proxy.* fields (gofilter boolean comparisons never match;
//     rejecting them loudly beats compiling a dead rule) and
//     except ip.quic (unregistered, reserved for Batch 3).
//   - `contains` only on string fields: on integer/IP fields it
//     can never match in gofilter either.
//   - Literals parse exactly as gofilter parses them for the
//     field's type: base-0 integers (0x/0o/0b/leading-zero), IP
//     addresses or CIDRs, and strings via Go unquoting, then
//     colon-hex bytes, then the raw text. Bare literals containing
//     the words and/or/not must be quoted.
//   - Actions use the same validation as general rules
//     (domains.ValidRuleAction).
//
// Equivalence: every accepted expression is first validated with
// gofilter.NewFilter, so the edge compiler can never accept an
// expression the general evaluator would refuse; the compiled
// check then replicates gofilter's comparison semantics,
// including its quirks (see domains.EdgeRule). Differential tests
// prove the two evaluators agree across the accepted grammar.
// Edge rules are config-file-only (edgeRules); they are not
// managed by the rule API, the simulator, or export/import.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/kor44/gofilter"

	"sonushield/core/domains"
)

// edgeFieldTypes mirrors the gofilter field registrations in
// filter.go, minus the boolean fields and ip.quic (see above).
var edgeFieldTypes = map[string]domains.EdgeFieldKind{
	"ip.src":                domains.EdgeFieldIP,
	"ip.country":            domains.EdgeFieldString,
	"ip.asn":                domains.EdgeFieldInt,
	"ip.engine":             domains.EdgeFieldString,
	"ip.bot":                domains.EdgeFieldString,
	"ip.fingerprint":        domains.EdgeFieldString,
	"ip.ja4":                domains.EdgeFieldString,
	"ip.reputation":         domains.EdgeFieldString,
	"ip.searchbot":          domains.EdgeFieldString,
	"ip.risk":               domains.EdgeFieldInt,
	"ip.timing":             domains.EdgeFieldString,
	"ip.requests":           domains.EdgeFieldInt,
	"ip.http_requests":      domains.EdgeFieldInt,
	"ip.challenge_requests": domains.EdgeFieldInt,

	"http.host":        domains.EdgeFieldString,
	"http.version":     domains.EdgeFieldString,
	"http.method":      domains.EdgeFieldString,
	"http.url":         domains.EdgeFieldString,
	"http.query":       domains.EdgeFieldString,
	"http.path":        domains.EdgeFieldString,
	"http.user_agent":  domains.EdgeFieldString,
	"http.cookie":      domains.EdgeFieldString,
	"http.headers":     domains.EdgeFieldString,
	"http.fingerprint": domains.EdgeFieldString,
	"http.http2":       domains.EdgeFieldString,
	"http.body":        domains.EdgeFieldString,

	"proxy.stage":       domains.EdgeFieldInt,
	"proxy.rps":         domains.EdgeFieldInt,
	"proxy.rps_allowed": domains.EdgeFieldInt,
}

var edgeOps = map[string]domains.EdgeOp{
	"eq":       domains.EdgeOpEq,
	"ne":       domains.EdgeOpNe,
	"gt":       domains.EdgeOpGt,
	"ge":       domains.EdgeOpGe,
	"lt":       domains.EdgeOpLt,
	"le":       domains.EdgeOpLe,
	"contains": domains.EdgeOpContains,
}

// CompileEdgeRule compiles one edge rule, or reports why the
// expression does not fit the fast grammar.
func CompileEdgeRule(expression, action string) (domains.EdgeRule, error) {
	if !domains.ValidRuleAction(action) {
		return domains.EdgeRule{}, fmt.Errorf("invalid action %q: must be an integer, +N, or -N", action)
	}
	// Anything gofilter rejects is rejected here too, so the edge
	// grammar stays a strict subset of valid general rules.
	if _, err := gofilter.NewFilter(expression); err != nil {
		return domains.EdgeRule{}, fmt.Errorf("invalid expression: %v", err)
	}
	field, opStr, literal, err := splitEdgeExpression(expression)
	if err != nil {
		return domains.EdgeRule{}, err
	}
	kind, ok := edgeFieldTypes[field]
	if !ok {
		return domains.EdgeRule{}, fmt.Errorf("field %q cannot be used in an edge rule (unknown, boolean, or reserved)", field)
	}
	op, ok := edgeOps[opStr]
	if !ok {
		return domains.EdgeRule{}, fmt.Errorf("operator %q is not supported in edge rules (use eq, ne, gt, ge, lt, le, contains)", opStr)
	}
	if edgeLiteralHasBooleanStructure(literal) {
		return domains.EdgeRule{}, fmt.Errorf("compound expressions are not supported in edge rules")
	}
	if op == domains.EdgeOpContains && kind != domains.EdgeFieldString {
		return domains.EdgeRule{}, fmt.Errorf("contains is only supported on string fields in edge rules")
	}
	rule := domains.EdgeRule{
		Expression: expression,
		Action:     action,
		Field:      field,
		Op:         op,
		Kind:       kind,
	}
	switch kind {
	case domains.EdgeFieldString:
		rule.StrVal = edgeParseStringLiteral(literal)
	case domains.EdgeFieldInt:
		value, err := strconv.ParseInt(literal, 0, 0)
		if err != nil {
			return domains.EdgeRule{}, fmt.Errorf("invalid integer literal %q", literal)
		}
		rule.IntVal = int(value)
	case domains.EdgeFieldIP:
		if ip := net.ParseIP(literal); ip != nil {
			rule.IPVal = ip.To16()
		} else if _, ipnet, err := net.ParseCIDR(literal); err == nil {
			ipnet.IP = ipnet.IP.To16()
			rule.IPNet = ipnet
			rule.IsCIDR = true
		} else {
			return domains.EdgeRule{}, fmt.Errorf("invalid IP literal %q", literal)
		}
	}
	return rule, nil
}

// CompileEdgeRules compiles a config edge-rule list. Rules that
// do not fit the fast grammar are skipped with one warning each;
// the caller prints the warnings at load time.
func CompileEdgeRules(raw []domains.JsonRule) ([]domains.EdgeRule, []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	compiled := make([]domains.EdgeRule, 0, len(raw))
	var warnings []string
	for i, rawRule := range raw {
		// Schedules (Batch 7) apply to general rules only;
		// an edge rule carrying one warns and ignores it.
		if strings.TrimSpace(rawRule.Schedule) != "" {
			warnings = append(warnings, fmt.Sprintf("edge rule %d (%q): schedule is ignored for edge rules; use firewallRules for scheduled rules", i, rawRule.Expression))
		}
		rule, err := CompileEdgeRule(rawRule.Expression, rawRule.Action)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("edge rule %d (%q): %v; skipped, use firewallRules for this expression", i, rawRule.Expression, err))
			continue
		}
		compiled = append(compiled, rule)
	}
	return compiled, warnings
}

// splitEdgeExpression splits a single-comparison expression into
// field, operator, and literal (the remainder, which may contain
// spaces when quoted).
func splitEdgeExpression(expression string) (field, op, literal string, err error) {
	rest := strings.TrimSpace(expression)
	i := strings.IndexFunc(rest, unicode.IsSpace)
	if i < 0 {
		return "", "", "", fmt.Errorf("expression must be `<field> <op> <literal>`")
	}
	field = rest[:i]
	rest = strings.TrimLeftFunc(rest[i:], unicode.IsSpace)
	j := strings.IndexFunc(rest, unicode.IsSpace)
	if j < 0 {
		return "", "", "", fmt.Errorf("expression must be `<field> <op> <literal>`")
	}
	op = rest[:j]
	literal = strings.TrimSpace(rest[j:])
	if literal == "" {
		return "", "", "", fmt.Errorf("expression must be `<field> <op> <literal>`")
	}
	return field, op, literal, nil
}

// edgeLiteralHasBooleanStructure reports whether a literal
// contains top-level boolean structure outside quotes: parentheses,
// &&, ||, !, or a whitespace-delimited and/or/not word. Quoted
// regions (double quotes with backslash escapes; backquotes are
// handled too, although gofilter's lexer rejects them before the
// scan ever runs) are skipped, so a literal like "rock and roll"
// is fine, while an unquoted compound is caught. Bare literals
// containing these words as hyphenated parts (x-and-y) are single
// tokens and are not flagged.
func edgeLiteralHasBooleanStructure(literal string) bool {
	// First pass: parentheses and symbolic operators outside quotes.
	inDouble, inBackquote := false, false
	for i := 0; i < len(literal); i++ {
		c := literal[i]
		if inDouble {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inBackquote {
			if c == '`' {
				inBackquote = false
			}
			continue
		}
		switch c {
		case '"':
			inDouble = true
		case '`':
			inBackquote = true
		case '(', ')', '!':
			return true
		case '&', '|':
			if i+1 < len(literal) && literal[i+1] == c {
				return true
			}
		}
	}
	// Second pass: whitespace-delimited boolean words outside quotes.
	// Mask quoted regions, then split on whitespace.
	masked := []byte(literal)
	inDouble, inBackquote = false, false
	for i := 0; i < len(masked); i++ {
		c := masked[i]
		if inDouble {
			masked[i] = ' '
			if c == '\\' && i+1 < len(masked) {
				masked[i+1] = ' '
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inBackquote {
			masked[i] = ' '
			if c == '`' {
				inBackquote = false
			}
			continue
		}
		switch c {
		case '"':
			inDouble = true
			masked[i] = ' '
		case '`':
			inBackquote = true
			masked[i] = ' '
		}
	}
	for _, word := range strings.Fields(string(masked)) {
		trimmed := strings.Trim(word, "()")
		if strings.EqualFold(trimmed, "and") || strings.EqualFold(trimmed, "or") || strings.EqualFold(trimmed, "not") {
			return true
		}
	}
	return false
}

// edgeParseStringLiteral parses a string literal exactly as
// gofilter's checkFieldNameVsTypeValue does for FT_STRING fields:
// Go unquoting first, then colon-hex bytes, then the raw text.
// The result is the literal's byte content as a Go string.
func edgeParseStringLiteral(data string) string {
	if str, err := strconv.Unquote(data); err == nil {
		return str
	}
	if b, ok := edgeParseBytes(data); ok {
		return string(b)
	}
	return data
}

// edgeParseBytes mirrors gofilter's parseBytes: colon-separated
// hex pairs. A single hex word with no colon also parses.
func edgeParseBytes(s string) ([]byte, bool) {
	parts := strings.Split(s, ":")
	b := make([]byte, 0, len(parts))
	for _, x := range parts {
		i, err := strconv.ParseUint(x, 16, 8)
		if err != nil {
			return nil, false
		}
		b = append(b, byte(i))
	}
	return b, true
}

// EvalEdgeRules evaluates the compiled edge chain, applying
// actions with the same helper as EvalFirewallRule. It returns
// the suspicion level and whether evaluation stopped (a
// plain-integer action set the level); when stopped, the caller
// must skip the general rules, exactly as if the edge rules were
// prepended to the general list.
func EvalEdgeRules(settings domains.DomainSettings, variables gofilter.Message, susLv int) (int, bool) {
	result := susLv
	for index, rule := range settings.EdgeRules {
		if rule.Matches(variables) {
			var stop bool
			result, stop = applyRuleAction(rule.Action, index, result)
			if stop {
				return result, true
			}
		}
	}
	return result, false
}

// MatchedEdgeRules lists the expressions of the edge rules that
// match, in chain order, mirroring MatchedRules for the general
// list. Used for logging and dry-run reporting.
func MatchedEdgeRules(settings domains.DomainSettings, variables gofilter.Message) []string {
	matched := []string{}
	for _, rule := range settings.EdgeRules {
		if rule.Matches(variables) {
			matched = append(matched, rule.Expression)
		}
	}
	return matched
}
