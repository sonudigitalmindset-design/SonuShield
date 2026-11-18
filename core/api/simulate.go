package api

// Rule simulator (Batch 4).
//
// SIMULATE_RULE evaluates one rule expression against
// operator-supplied sample request fields and reports whether it
// matches and which fields the expression used, without enforcing
// anything. Params: expression (required, 4 KB cap) and sample
// (optional JSON object, 10 KB cap).
//
// The sample is coerced onto the same field types the request
// path populates: net.IP for ip.src, integers for the counters
// and stage, booleans for the proxy flags, strings for the rest.
// Every known field starts at its zero value, so a sample only
// needs the fields the expression cares about. Unknown sample
// fields are rejected, so a typo cannot silently simulate the
// wrong request.

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/kor44/gofilter"
)

const (
	maxSimulateExpression = 4 << 10  // 4 KB
	maxSimulateSample     = 10 << 10 // 10 KB
)

var simulateIntFields = map[string]bool{
	"ip.asn": true, "ip.risk": true, "ip.http_requests": true, "ip.challenge_requests": true,
	"proxy.stage": true, "proxy.rps": true, "proxy.rps_allowed": true,
}

var simulateBoolFields = map[string]bool{
	"proxy.cloudflare": true, "proxy.stage_locked": true,
	"proxy.attack": true, "proxy.bypass_attack": true,
}

// simulateRule evaluates one expression against one sample and
// returns the match result plus the fields the expression used.
func simulateRule(params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		if key != "expression" && key != "sample" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	expression, ok := params["expression"]
	if !ok {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	if len(expression) > maxSimulateExpression {
		return nil, ERR_INVALID_PARAM, "expression too large"
	}
	if err := validateRuleExpression(expression); err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	variables, err := sampleVariables(params["sample"])
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	filter, err := gofilter.NewFilter(expression)
	if err != nil {
		return nil, ERR_INVALID_PARAM, "expression does not compile: " + err.Error()
	}
	return map[string]interface{}{
		"MATCH":       filter.Apply(variables),
		"FIELDS_USED": fieldsUsed(expression),
	}, "", ""
}

// sampleVariables builds the evaluation message: zero values for
// every known field, overlaid with the coerced sample.
func sampleVariables(sample string) (gofilter.Message, error) {
	variables := gofilter.Message{
		"ip.src":                net.ParseIP("0.0.0.0"),
		"ip.country":            "",
		"ip.asn":                0,
		"ip.engine":             "",
		"ip.bot":                "",
		"ip.fingerprint":        "",
		"ip.ja4":                "",
		"ip.quic":               "",
		"ip.reputation":         "",
		"ip.searchbot":          "",
		"ip.risk":               0,
		"ip.timing":             "",
		"ip.http_requests":      0,
		"ip.challenge_requests": 0,

		"http.host":        "",
		"http.version":     "",
		"http.method":      "",
		"http.url":         "",
		"http.query":       "",
		"http.path":        "",
		"http.user_agent":  "",
		"http.cookie":      "",
		"http.fingerprint": "",
		"http.http2":       "",

		"proxy.stage":         0,
		"proxy.cloudflare":    false,
		"proxy.stage_locked":  false,
		"proxy.attack":        false,
		"proxy.bypass_attack": false,
		"proxy.rps":           0,
		"proxy.rps_allowed":   0,
	}
	if strings.TrimSpace(sample) == "" {
		return variables, nil
	}
	if len(sample) > maxSimulateSample {
		return nil, errors.New("sample too large")
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(sample))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return nil, errors.New("sample is not a JSON object: " + err.Error())
	}
	if raw == nil {
		return nil, errors.New("sample is not a JSON object")
	}
	for field, value := range raw {
		if !ruleFields[field] {
			return nil, errors.New("unknown sample field: " + field)
		}
		coerced, err := coerceSampleValue(field, value)
		if err != nil {
			return nil, err
		}
		variables[field] = coerced
	}
	return variables, nil
}

// coerceSampleValue converts one JSON sample value to the Go type
// the request path stores for that field. JSON strings are also
// accepted for numbers, booleans, and ip.src, so samples are easy
// to write by hand.
func coerceSampleValue(field string, raw json.RawMessage) (interface{}, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch {
		case field == "ip.src":
			parsed := net.ParseIP(text)
			if parsed == nil {
				return nil, errors.New("sample field ip.src is not a valid IP: " + text)
			}
			return parsed, nil
		case simulateIntFields[field]:
			parsed, err := strconv.Atoi(text)
			if err != nil {
				return nil, errors.New("sample field " + field + " is not an integer")
			}
			return parsed, nil
		case simulateBoolFields[field]:
			parsed, err := strconv.ParseBool(text)
			if err != nil {
				return nil, errors.New("sample field " + field + " is not a boolean")
			}
			return parsed, nil
		default:
			return text, nil
		}
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		if !simulateIntFields[field] {
			return nil, errors.New("sample field " + field + " must be a string")
		}
		parsed, err := number.Int64()
		if err != nil {
			return nil, errors.New("sample field " + field + " is not an integer")
		}
		return int(parsed), nil
	}
	var boolean bool
	if err := json.Unmarshal(raw, &boolean); err == nil {
		if !simulateBoolFields[field] {
			return nil, errors.New("sample field " + field + " must be a string")
		}
		return boolean, nil
	}
	return nil, errors.New("sample field " + field + " has an unsupported value")
}

// fieldsUsed lists the dotted field names an expression
// references, in order of first appearance, deduplicated.
// String literals are stripped first so dotted text inside a
// literal is never reported as a field.
func fieldsUsed(expression string) []string {
	stripped := ruleStringLiteral.ReplaceAllString(expression, `""`)
	seen := map[string]bool{}
	used := []string{}
	for _, token := range ruleFieldToken.FindAllString(stripped, -1) {
		if !seen[token] {
			seen[token] = true
			used = append(used, token)
		}
	}
	return used
}
