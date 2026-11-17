package domains

// GraphQL query depth / complexity approximation (Batch 4).
//
// This is deliberately NOT a full GraphQL parser: it strips
// string literals and comments, then measures brace-nesting
// depth and counts field-name identifiers. That is enough to
// reject the deeply-nested or field-stuffed queries the limit
// exists for, without depending on a GraphQL library. The
// counts are an approximation and are documented as such; a
// query that only looks complex (for example, many arguments)
// may count slightly high, and one hidden inside fragments may
// count slightly low. Limits apply only when the operator
// configures them, and only on the configured GraphQL path.

import (
	"strings"
)

var graphqlKeywords = map[string]bool{
	"query": true, "mutation": true, "subscription": true,
	"fragment": true, "on": true,
	"true": true, "false": true, "null": true,
}

// AnalyzeGraphQLQuery returns the maximum brace-nesting depth
// and the number of field-name identifiers in a query string.
func AnalyzeGraphQLQuery(query string) (depth, fields int) {
	cleaned := stripGraphQLStringsAndComments(query)
	current := 0
	runes := []rune(cleaned)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '{':
			current++
			if current > depth {
				depth = current
			}
		case '}':
			if current > 0 {
				current--
			}
		case '(', '[', ']', ')', ':', ',', '$', '!', '@', '=', '|', '&', '.', '<', '>':
			// Punctuation: never a field name.
		default:
			if isGraphQLIdentStart(runes[i]) {
				start := i
				for i < len(runes) && isGraphQLIdentPart(runes[i]) {
					i++
				}
				name := string(runes[start:i])
				i--
				if graphqlKeywords[name] {
					continue
				}
				// An identifier followed by ":" is an argument
				// or alias name, not a field.
				j := i + 1
				for j < len(runes) && (runes[j] == ' ' || runes[j] == '\t' || runes[j] == '\n' || runes[j] == '\r') {
					j++
				}
				if j < len(runes) && runes[j] == ':' {
					continue
				}
				fields++
			}
		}
	}
	return depth, fields
}

func isGraphQLIdentStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isGraphQLIdentPart(r rune) bool {
	return isGraphQLIdentStart(r) || (r >= '0' && r <= '9')
}

// stripGraphQLStringsAndComments removes double-quoted strings
// (with backslash escapes), block strings ("""), and # comments,
// replacing their contents with spaces so positions stay stable.
func stripGraphQLStringsAndComments(query string) string {
	var out strings.Builder
	out.Grow(len(query))
	runes := []rune(query)
	for i := 0; i < len(runes); i++ {
		switch {
		case runes[i] == '#':
			for i < len(runes) && runes[i] != '\n' {
				out.WriteRune(' ')
				i++
			}
			if i < len(runes) {
				out.WriteRune('\n')
			}
		case i+2 < len(runes) && runes[i] == '"' && runes[i+1] == '"' && runes[i+2] == '"':
			out.WriteString("   ")
			i += 3
			for i+2 < len(runes) && !(runes[i] == '"' && runes[i+1] == '"' && runes[i+2] == '"') {
				if runes[i] == '\n' {
					out.WriteRune('\n')
				} else {
					out.WriteRune(' ')
				}
				i++
			}
			if i+2 < len(runes) {
				out.WriteString("   ")
				i += 2
			}
		case runes[i] == '"':
			out.WriteRune(' ')
			i++
			for i < len(runes) && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < len(runes) {
					out.WriteString("  ")
					i += 2
					continue
				}
				out.WriteRune(' ')
				i++
			}
			if i < len(runes) {
				out.WriteRune(' ')
			}
		default:
			out.WriteRune(runes[i])
		}
	}
	return out.String()
}
