package api

// Cloudflare expression translator (Batch 7).
//
// Translates the documented subset of Cloudflare firewall
// expressions (wirefilter syntax) into SonuShield gofilter
// expressions:
//
//	Fields:    ip.src, http.request.uri.path,
//	           http.user_agent, http.request.method,
//	           cf.client.bot
//	Operators: eq, ne, gt, ge, lt, le, contains, matches,
//	           starts_with, ends_with, in, not in
//	Combinators: and, or, not, parentheses
//
// Everything outside the subset — other fields, other
// operators, functions, lists — fails translation, and the
// rule is skipped with a reason in the import plan. Nothing
// is silently approximated except the two cases documented
// below, which are flagged in the plan:
//
//   - starts_with / ends_with become anchored regex matches
//     (gofilter has no prefix/suffix operator): the literal
//     is regexp-quoted, so the match stays exact.
//   - cf.client.bot becomes a test on ip.bot (the
//     known-bot fingerprint list): "bot" means a
//     recognised bot fingerprint, which is NOT equivalent
//     to Cloudflare Bot Management. The plan flags every
//     rule that uses it.
//
// IP values are emitted bare (gofilter rejects quoted IP
// literals) and must parse as an IP or CIDR. String values
// are emitted Go-quoted, which gofilter unquotes. The
// translated expression is always re-validated with the
// rule validator before it can be applied, so a translation
// the engine cannot compile is skipped, never stored.

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// cfFieldKind classifies a translatable Cloudflare field.
type cfFieldKind int

const (
	cfFieldIP cfFieldKind = iota
	cfFieldString
	cfFieldBool
)

// cfField maps a Cloudflare field name to its SonuShield
// equivalent and kind.
type cfField struct {
	sonushield string
	kind       cfFieldKind
}

var cfFields = map[string]cfField{
	"ip.src":                {"ip.src", cfFieldIP},
	"http.request.uri.path": {"http.path", cfFieldString},
	"http.user_agent":       {"http.user_agent", cfFieldString},
	"http.request.method":   {"http.method", cfFieldString},
	"cf.client.bot":         {"ip.bot", cfFieldBool},
}

// cfTokenKind classifies expression tokens.
type cfTokenKind int

const (
	cfTokLParen cfTokenKind = iota
	cfTokRParen
	cfTokLBrace
	cfTokRBrace
	cfTokWord   // identifiers, operators, bare values
	cfTokString // decoded quoted string
)

type cfToken struct {
	kind cfTokenKind
	text string
}

// tokenizeCFExpression splits a Cloudflare expression into
// tokens. Quoted strings are decoded; commas are skipped
// (lenient set separators).
func tokenizeCFExpression(expr string) ([]cfToken, error) {
	var tokens []cfToken
	i := 0
	for i < len(expr) {
		ch := expr[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			i++
		case ch == '(':
			tokens = append(tokens, cfToken{cfTokLParen, "("})
			i++
		case ch == ')':
			tokens = append(tokens, cfToken{cfTokRParen, ")"})
			i++
		case ch == '{':
			tokens = append(tokens, cfToken{cfTokLBrace, "{"})
			i++
		case ch == '}':
			tokens = append(tokens, cfToken{cfTokRBrace, "}"})
			i++
		case ch == ',':
			i++
		case ch == '"':
			value, next, err := scanCFString(expr, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, cfToken{cfTokString, value})
			i = next
		default:
			j := i
			for j < len(expr) {
				c := expr[j]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' || c == '{' || c == '}' || c == ',' {
					break
				}
				j++
			}
			tokens = append(tokens, cfToken{cfTokWord, expr[i:j]})
			i = j
		}
	}
	return tokens, nil
}

// scanCFString decodes a double-quoted string starting at
// expr[start] == '"', returning the value and the index
// just past the closing quote.
func scanCFString(expr string, start int) (string, int, error) {
	var b strings.Builder
	i := start + 1
	for i < len(expr) {
		ch := expr[i]
		if ch == '"' {
			return b.String(), i + 1, nil
		}
		if ch == '\\' && i+1 < len(expr) {
			switch expr[i+1] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '/':
				b.WriteByte('/')
			default:
				b.WriteByte(expr[i+1])
			}
			i += 2
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return "", 0, errors.New("unterminated string literal")
}

// cfParser is a recursive-descent parser over CF tokens.
type cfParser struct {
	tokens []cfToken
	pos    int
	notes  []string // translation caveats, e.g. bot approximation
}

func (p *cfParser) peek() (cfToken, bool) {
	if p.pos >= len(p.tokens) {
		return cfToken{}, false
	}
	return p.tokens[p.pos], true
}

func (p *cfParser) next() (cfToken, bool) {
	tok, ok := p.peek()
	if ok {
		p.pos++
	}
	return tok, ok
}

func (p *cfParser) expectWord(word string) bool {
	tok, ok := p.peek()
	if ok && tok.kind == cfTokWord && tok.text == word {
		p.pos++
		return true
	}
	return false
}

// translateCFExpression translates one Cloudflare filter
// expression. It returns the SonuShield expression and any
// caveat notes, or an error describing why the rule must be
// skipped.
func translateCFExpression(expr string) (string, []string, error) {
	tokens, err := tokenizeCFExpression(expr)
	if err != nil {
		return "", nil, err
	}
	if len(tokens) == 0 {
		return "", nil, errors.New("empty expression")
	}
	parser := &cfParser{tokens: tokens}
	translated, err := parser.parseOr()
	if err != nil {
		return "", nil, err
	}
	if parser.pos != len(tokens) {
		return "", nil, fmt.Errorf("unexpected trailing input %q", tokens[parser.pos].text)
	}
	return translated, parser.notes, nil
}

func (p *cfParser) parseOr() (string, error) {
	left, err := p.parseAnd()
	if err != nil {
		return "", err
	}
	for {
		tok, ok := p.peek()
		if !ok || tok.kind != cfTokWord || (tok.text != "or" && tok.text != "OR" && tok.text != "||") {
			return left, nil
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return "", err
		}
		left = "(" + left + " or " + right + ")"
	}
}

func (p *cfParser) parseAnd() (string, error) {
	left, err := p.parseNot()
	if err != nil {
		return "", err
	}
	for {
		tok, ok := p.peek()
		if !ok || tok.kind != cfTokWord || (tok.text != "and" && tok.text != "AND" && tok.text != "&&") {
			return left, nil
		}
		p.pos++
		right, err := p.parseNot()
		if err != nil {
			return "", err
		}
		left = "(" + left + " and " + right + ")"
	}
}

func (p *cfParser) parseNot() (string, error) {
	tok, ok := p.peek()
	if ok && tok.kind == cfTokWord && (tok.text == "not" || tok.text == "NOT" || tok.text == "!") {
		p.pos++
		inner, err := p.parseNot()
		if err != nil {
			return "", err
		}
		return "not (" + inner + ")", nil
	}
	return p.parsePrimary()
}

func (p *cfParser) parsePrimary() (string, error) {
	tok, ok := p.next()
	if !ok {
		return "", errors.New("unexpected end of expression")
	}
	if tok.kind == cfTokLParen {
		inner, err := p.parseOr()
		if err != nil {
			return "", err
		}
		closing, ok := p.next()
		if !ok || closing.kind != cfTokRParen {
			return "", errors.New("missing closing parenthesis")
		}
		return "(" + inner + ")", nil
	}
	if tok.kind != cfTokWord {
		return "", fmt.Errorf("expected a field name, got %q", tok.text)
	}
	// A comparison starts with a field name; step back so
	// parseComparison consumes it.
	p.pos--
	return p.parseComparison()
}

func (p *cfParser) parseComparison() (string, error) {
	fieldTok, _ := p.next()
	field, ok := cfFields[fieldTok.text]
	if !ok {
		return "", fmt.Errorf("unsupported field %q", fieldTok.text)
	}
	opTok, ok := p.next()
	if !ok {
		return "", fmt.Errorf("missing operator after field %q", fieldTok.text)
	}
	negated := false
	if opTok.kind == cfTokWord && opTok.text == "not" {
		// Only "not in" is valid here.
		inTok, ok := p.next()
		if !ok || inTok.kind != cfTokWord || inTok.text != "in" {
			return "", fmt.Errorf("expected \"in\" after \"not\" for field %q", fieldTok.text)
		}
		negated = true
		opTok = inTok
	}
	if opTok.kind != cfTokWord {
		return "", fmt.Errorf("expected an operator after field %q", fieldTok.text)
	}
	op := opTok.text
	if op == "in" {
		return p.parseSet(field, fieldTok.text, negated)
	}
	if negated {
		return "", fmt.Errorf("unexpected \"not\" before operator %q", op)
	}
	valueTok, ok := p.next()
	if !ok {
		return "", fmt.Errorf("missing value after operator %q", op)
	}
	return p.translatePredicate(field, fieldTok.text, op, valueTok)
}

// parseSet translates "field [not] in { v1 v2 ... }" into an
// or-chain of equality tests.
func (p *cfParser) parseSet(field cfField, fieldName string, negated bool) (string, error) {
	open, ok := p.next()
	if !ok || open.kind != cfTokLBrace {
		return "", fmt.Errorf("expected \"{\" after \"in\" for field %q", fieldName)
	}
	var values []cfToken
	for {
		tok, ok := p.next()
		if !ok {
			return "", fmt.Errorf("unterminated set for field %q", fieldName)
		}
		if tok.kind == cfTokRBrace {
			break
		}
		if tok.kind != cfTokWord && tok.kind != cfTokString {
			return "", fmt.Errorf("unexpected token %q in set for field %q", tok.text, fieldName)
		}
		values = append(values, tok)
	}
	if len(values) == 0 {
		return "", fmt.Errorf("empty set for field %q", fieldName)
	}
	parts := make([]string, 0, len(values))
	for _, valueTok := range values {
		part, err := p.translatePredicate(field, fieldName, "eq", valueTok)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	joined := strings.Join(parts, " or ")
	if len(parts) > 1 {
		joined = "(" + joined + ")"
	}
	if negated {
		return "not (" + joined + ")", nil
	}
	return joined, nil
}

// translatePredicate translates one field/operator/value
// comparison.
func (p *cfParser) translatePredicate(field cfField, fieldName, op string, valueTok cfToken) (string, error) {
	switch op {
	case "==":
		op = "eq"
	case "!=":
		op = "ne"
	}
	switch field.kind {
	case cfFieldBool:
		return p.translateBoolPredicate(field, fieldName, op, valueTok)
	case cfFieldIP:
		return p.translateIPPredicate(field, fieldName, op, valueTok)
	default:
		return p.translateStringPredicate(field, fieldName, op, valueTok)
	}
}

func (p *cfParser) translateBoolPredicate(field cfField, fieldName, op string, valueTok cfToken) (string, error) {
	if valueTok.kind != cfTokWord || (valueTok.text != "true" && valueTok.text != "false") {
		return "", fmt.Errorf("field %q needs a true/false value", fieldName)
	}
	wantBot := valueTok.text == "true"
	if op == "ne" {
		wantBot = !wantBot
	} else if op != "eq" {
		return "", fmt.Errorf("operator %q is not supported for field %q", op, fieldName)
	}
	p.notes = append(p.notes, "cf.client.bot is approximated by the SonuShield known-bot fingerprint (ip.bot); it is not equivalent to Cloudflare Bot Management")
	if wantBot {
		return `ip.bot ne ""`, nil
	}
	return `ip.bot eq ""`, nil
}

func (p *cfParser) translateIPPredicate(field cfField, fieldName, op string, valueTok cfToken) (string, error) {
	if op != "eq" && op != "ne" {
		return "", fmt.Errorf("operator %q is not supported for field %q", op, fieldName)
	}
	value := valueTok.text
	if net.ParseIP(value) == nil {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return "", fmt.Errorf("value %q for field %q is not an IP address or CIDR", value, fieldName)
		}
	}
	return field.sonushield + " " + op + " " + value, nil
}

func (p *cfParser) translateStringPredicate(field cfField, fieldName, op string, valueTok cfToken) (string, error) {
	value := valueTok.text
	quoted := strconv.Quote(value)
	switch op {
	case "eq", "ne", "gt", "ge", "lt", "le", "contains", "matches":
		return field.sonushield + " " + op + " " + quoted, nil
	case "starts_with":
		return field.sonushield + " matches " + strconv.Quote("^"+regexp.QuoteMeta(value)), nil
	case "ends_with":
		return field.sonushield + " matches " + strconv.Quote(regexp.QuoteMeta(value)+"$"), nil
	default:
		return "", fmt.Errorf("operator %q is not supported for field %q", op, fieldName)
	}
}

// translateCFAction maps a Cloudflare firewall action to a
// SonuShield rule action. The second return value is false
// when the action has no equivalent.
func translateCFAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block":
		return "4", true
	case "challenge", "js_challenge", "managed_challenge":
		return "2", true
	case "allow":
		return "0", true
	default:
		return "", false
	}
}
