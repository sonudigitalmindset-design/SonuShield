package domains

// OpenAPI request validation (Batch 8).
//
// A domain can validate API requests against an operator-
// supplied OpenAPI 3.x document (JSON only; YAML documents
// must be converted with a tool like yq first). Validation
// applies only to requests under the configured path prefixes,
// so non-API traffic on the same domain is untouched.
//
// What is checked, for a request under a validated prefix:
//   - The path matches a path template in the spec (with
//     {parameter} segments matching one path segment), and
//     the method is defined for it.
//   - Required query, header, and path parameters are
//     present, with basic type and enum checks.
//   - A JSON request body conforms to the operation's schema:
//     object/array/scalar types, required properties,
//     nested properties and array items, enums, numeric
//     bounds, string length bounds, and patterns.
//
// The schema subset is deliberately small and documented:
// $ref is resolved only for local "#/components/schemas/..."
// references; allOf/oneOf/anyOf, discriminator, and format
// assertions are not evaluated (a schema using only those
// keywords validates as unconstrained). A body that is not
// valid JSON, or larger than the validation cap, counts as a
// violation in block mode and is logged in log mode.
//
// Modes: "log" (default, fail-open — violations are logged and
// the request continues) or "block" (fail-closed — violations
// get a generic 400). The mode is configurable per route
// prefix via Routes; the longest matching prefix wins, else
// the global mode applies. An invalid or unreadable spec file
// disables validation with a startup warning: a bad spec can
// never take enforcement down with it, and never blocks
// traffic. Violation log entries name the rule and field only;
// request bodies are never logged.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// OpenAPIConfig is the per-domain OpenAPI configuration
// (domain.openApi). SpecFile is the JSON document path,
// relative to the proxy working directory. Prefixes lists the
// path prefixes validated against the spec (empty means the
// feature is off). Mode is the global mode ("log" default,
// "block"). Routes overrides the mode per path prefix.
type OpenAPIConfig struct {
	SpecFile string           `json:"specFile"`
	Prefixes []string         `json:"prefixes"`
	Mode     string           `json:"mode"`
	Routes   []OpenAPIRoute   `json:"routes"`
}

// OpenAPIRoute overrides the validation mode for one path
// prefix. Prefix is matched with the longest-prefix rule;
// Mode is "log" or "block".
type OpenAPIRoute struct {
	Prefix string `json:"prefix"`
	Mode   string `json:"mode"`
}

// openAPISchema is the subset of JSON Schema used for request
// bodies, plus OpenAPI parameter declarations.
type openAPISchema struct {
	Ref          string                    `json:"$ref"`
	Type         string                    `json:"type"`
	Required     []string                  `json:"required"`
	Properties   map[string]openAPISchema  `json:"properties"`
	Items        *openAPISchema            `json:"items"`
	Enum         []interface{}             `json:"enum"`
	Minimum      *float64                  `json:"minimum"`
	Maximum      *float64                  `json:"maximum"`
	MinLength    *int                      `json:"minLength"`
	MaxLength    *int                      `json:"maxLength"`
	Pattern      string                    `json:"pattern"`
	// Additional holds additionalProperties verbatim: only a
	// boolean false is enforced (unknown keys rejected). A
	// schema-valued additionalProperties is accepted by the
	// parser and treated as unconstrained — see
	// additionalForbidden.
	Additional   json.RawMessage         `json:"additionalProperties"`
}

type openAPIParameter struct {
	Name     string        `json:"name"`
	In       string        `json:"in"`
	Required bool          `json:"required"`
	Schema   openAPISchema `json:"schema"`
}

type openAPIOperation struct {
	Parameters  []openAPIParameter `json:"parameters"`
	RequestBody *struct {
		Required bool `json:"required"`
		Content  map[string]struct {
			Schema openAPISchema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type openAPIDocument struct {
	OpenAPI    string `json:"openapi"`
	Paths      map[string]map[string]openAPIOperation `json:"paths"`
	Components *struct {
		Schemas map[string]openAPISchema `json:"schemas"`
	} `json:"components"`
}

// OpenAPISpec is a loaded, validated spec ready for request
// checking. A nil spec means validation is disabled.
type OpenAPISpec struct {
	prefixes  []string
	blockMode bool
	routes    []OpenAPIRoute
	paths     map[string]map[string]openAPIOperation
	schemas   map[string]openAPISchema
	patterns  map[string]*regexp.Regexp
	checked   atomic.Int64
	violated  atomic.Int64
}

// NewOpenAPISpec loads and validates a spec file, or returns
// nil when validation is not configured. An unreadable,
// malformed, or unsupported document logs a warning and
// returns nil (fail safe: no enforcement).
func NewOpenAPISpec(domainName string, cfg OpenAPIConfig) *OpenAPISpec {
	if cfg.SpecFile == "" || len(cfg.Prefixes) == 0 {
		return nil
	}
	data, err := os.ReadFile(cfg.SpecFile)
	if err != nil {
		fmt.Println("[ ! ] [ OpenAPI spec unreadable for " + domainName + ": " + err.Error() + "; request validation disabled ]")
		return nil
	}
	var doc openAPIDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Println("[ ! ] [ OpenAPI spec malformed for " + domainName + ": " + err.Error() + "; request validation disabled ]")
		return nil
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		fmt.Println("[ ! ] [ OpenAPI spec for " + domainName + " is not an OpenAPI 3.x document; request validation disabled ]")
		return nil
	}
	if len(doc.Paths) == 0 {
		fmt.Println("[ ! ] [ OpenAPI spec for " + domainName + " defines no paths; request validation disabled ]")
		return nil
	}
	spec := &OpenAPISpec{
		prefixes:  cfg.Prefixes,
		blockMode: strings.ToLower(strings.TrimSpace(cfg.Mode)) == "block",
		routes:    cfg.Routes,
		paths:     doc.Paths,
	}
	if doc.Components != nil {
		spec.schemas = doc.Components.Schemas
	}
	// Precompile patterns so a bad pattern fails at load, not
	// per request. A bad pattern disables validation: the spec
	// cannot be trusted as written.
	spec.patterns = map[string]*regexp.Regexp{}
	if !spec.compilePatterns() {
		fmt.Println("[ ! ] [ OpenAPI spec for " + domainName + " has an invalid pattern; request validation disabled ]")
		return nil
	}
	return spec
}

// compilePatterns compiles every pattern in the document into
// the pattern cache, resolving through shared schemas. It
// reports false when any pattern fails to compile.
func (s *OpenAPISpec) compilePatterns() bool {
	ok := true
	var walk func(schema openAPISchema)
	walk = func(schema openAPISchema) {
		if schema.Pattern != "" {
			if _, cached := s.patterns[schema.Pattern]; !cached {
				compiled, err := regexp.Compile(schema.Pattern)
				if err != nil {
					ok = false
					return
				}
				s.patterns[schema.Pattern] = compiled
			}
		}
		for _, prop := range schema.Properties {
			walk(prop)
		}
		if schema.Items != nil {
			walk(*schema.Items)
		}
	}
	for _, operations := range s.paths {
		for _, operation := range operations {
			for _, param := range operation.Parameters {
				walk(param.Schema)
			}
			if operation.RequestBody != nil {
				for _, media := range operation.RequestBody.Content {
					walk(media.Schema)
				}
			}
		}
	}
	for _, schema := range s.schemas {
		walk(schema)
	}
	return ok
}

// Validated reports whether path falls under validation.
func (s *OpenAPISpec) Validated(path string) bool {
	if s == nil {
		return false
	}
	for _, prefix := range s.prefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// BlockMode reports whether violations block for this path,
// honoring per-route overrides (longest prefix wins).
func (s *OpenAPISpec) BlockMode(path string) bool {
	if s == nil {
		return false
	}
	best := -1
	block := s.blockMode
	for _, route := range s.routes {
		if route.Prefix != "" && strings.HasPrefix(path, route.Prefix) && len(route.Prefix) > best {
			best = len(route.Prefix)
			block = strings.ToLower(strings.TrimSpace(route.Mode)) == "block"
		}
	}
	return block
}

// Stats reports the request/validation counters and the number
// of paths in the spec.
func (s *OpenAPISpec) Stats() (paths, checked, violated int64) {
	if s == nil {
		return 0, 0, 0
	}
	return int64(len(s.paths)), s.checked.Load(), s.violated.Load()
}

// matchPath finds the operation for a method + path, resolving
// path templates. It returns the operation and the extracted
// path parameters.
func (s *OpenAPISpec) matchPath(method, path string) (openAPIOperation, map[string]string, bool) {
	method = strings.ToLower(method)
	pathSegments := splitPath(path)
	for template, operations := range s.paths {
		params, ok := matchTemplate(template, pathSegments)
		if !ok {
			continue
		}
		operation, ok := operations[method]
		if !ok {
			return openAPIOperation{}, nil, false
		}
		return operation, params, true
	}
	return openAPIOperation{}, nil, false
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func matchTemplate(template string, segments []string) (map[string]string, bool) {
	templateSegments := splitPath(template)
	if len(templateSegments) != len(segments) {
		return nil, false
	}
	params := map[string]string{}
	for i, seg := range templateSegments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			params[seg[1:len(seg)-1]] = segments[i]
			continue
		}
		if seg != segments[i] {
			return nil, false
		}
	}
	return params, true
}

// Validate checks a request: method, path, parameters, and an
// optional JSON body. It returns "" when the request conforms,
// or a short violation description (rule + field, never body
// content) when it does not. body is nil when the request has
// no body or the body could not be read within the cap; a nil
// body with a required requestBody schema is a violation.
func (s *OpenAPISpec) Validate(method, path string, query map[string][]string, headers map[string]string, body []byte, hasBody bool) string {
	if s == nil {
		return ""
	}
	s.checked.Add(1)
	violation := s.validate(method, path, query, headers, body, hasBody)
	if violation != "" {
		s.violated.Add(1)
	}
	return violation
}

func (s *OpenAPISpec) validate(method, path string, query map[string][]string, headers map[string]string, body []byte, hasBody bool) string {
	operation, pathParams, ok := s.matchPath(method, path)
	if !ok {
		if s.pathKnown(path) {
			return "unknown_operation"
		}
		return "unknown_path"
	}
	for _, param := range operation.Parameters {
		var value string
		var present bool
		switch param.In {
		case "query":
			values, ok := query[param.Name]
			present = ok && len(values) > 0
			if present {
				value = values[0]
			}
		case "header":
			value, present = headers[strings.ToLower(param.Name)]
		case "path":
			value, present = pathParams[param.Name]
		default:
			continue
		}
		if !present {
			if param.Required {
				return "missing_parameter:" + param.In + ":" + param.Name
			}
			continue
		}
		if violation := s.checkScalar(param.Schema, value, "parameter:"+param.In+":"+param.Name); violation != "" {
			return violation
		}
	}
	if operation.RequestBody != nil {
		schema, hasSchema := requestBodySchema(operation)
		if hasSchema {
			if !hasBody {
				if operation.RequestBody.Required {
					return "missing_body"
				}
				return ""
			}
			if body == nil {
				return "unreadable_body"
			}
			var decoded interface{}
			if err := json.Unmarshal(body, &decoded); err != nil {
				return "invalid_json_body"
			}
			if violation := s.checkValue(schema, decoded, "body"); violation != "" {
				return violation
			}
		}
	}
	return ""
}

// pathKnown reports whether any template matches the path,
// regardless of method.
func (s *OpenAPISpec) pathKnown(path string) bool {
	segments := splitPath(path)
	for template := range s.paths {
		if _, ok := matchTemplate(template, segments); ok {
			return true
		}
	}
	return false
}

func requestBodySchema(operation openAPIOperation) (openAPISchema, bool) {
	if operation.RequestBody == nil {
		return openAPISchema{}, false
	}
	for mediaType, media := range operation.RequestBody.Content {
		if strings.HasPrefix(strings.ToLower(mediaType), "application/json") {
			return media.Schema, true
		}
	}
	return openAPISchema{}, false
}

// resolve follows a local $ref to a shared schema. Unknown or
// non-local references resolve to an unconstrained schema:
// validation never fails on an unresolvable reference.
func (s *OpenAPISpec) resolve(schema openAPISchema) openAPISchema {
	if schema.Ref == "" {
		return schema
	}
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(schema.Ref, prefix) {
		return openAPISchema{}
	}
	name := schema.Ref[len(prefix):]
	if resolved, ok := s.schemas[name]; ok {
		return resolved
	}
	return openAPISchema{}
}

// checkScalar validates one scalar string value (query, header,
// or path parameter) against a schema's type and enum.
func (s *OpenAPISpec) checkScalar(schema openAPISchema, value, where string) string {
	schema = s.resolve(schema)
	if len(schema.Enum) > 0 {
		matched := false
		for _, allowed := range schema.Enum {
			if fmt.Sprint(allowed) == value {
				matched = true
				break
			}
		}
		if !matched {
			return "invalid_enum:" + where
		}
	}
	switch schema.Type {
	case "", "string":
		if schema.Pattern != "" {
			if re, ok := s.patterns[schema.Pattern]; ok && !re.MatchString(value) {
				return "pattern_mismatch:" + where
			}
		}
		if schema.MinLength != nil && len(value) < *schema.MinLength {
			return "too_short:" + where
		}
		if schema.MaxLength != nil && len(value) > *schema.MaxLength {
			return "too_long:" + where
		}
	case "integer":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return "invalid_integer:" + where
		}
		if violation := checkNumericBounds(schema, float64(n), where); violation != "" {
			return violation
		}
	case "number":
		n, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return "invalid_number:" + where
		}
		if violation := checkNumericBounds(schema, n, where); violation != "" {
			return violation
		}
	case "boolean":
		if value != "true" && value != "false" {
			return "invalid_boolean:" + where
		}
	}
	return ""
}

func checkNumericBounds(schema openAPISchema, n float64, where string) string {
	if schema.Minimum != nil && n < *schema.Minimum {
		return "below_minimum:" + where
	}
	if schema.Maximum != nil && n > *schema.Maximum {
		return "above_maximum:" + where
	}
	return ""
}

// checkValue validates a decoded JSON value against a schema,
// recursively. where names the field path for the violation
// message; values are never included.
func (s *OpenAPISpec) checkValue(schema openAPISchema, value interface{}, where string) string {
	schema = s.resolve(schema)
	if len(schema.Enum) > 0 {
		matched := false
		for _, allowed := range schema.Enum {
			if jsonEqual(allowed, value) {
				matched = true
				break
			}
		}
		if !matched {
			return "invalid_enum:" + where
		}
	}
	switch schema.Type {
	case "":
		return ""
	case "object":
		obj, ok := value.(map[string]interface{})
		if !ok {
			return "wrong_type:" + where
		}
		for _, required := range schema.Required {
			if _, ok := obj[required]; !ok {
				return "missing_property:" + where + "." + required
			}
		}
		for name, propSchema := range schema.Properties {
			if propValue, ok := obj[name]; ok {
				if violation := s.checkValue(propSchema, propValue, where+"."+name); violation != "" {
					return violation
				}
			}
		}
		if additionalForbidden(schema.Additional) {
			for name := range obj {
				if _, known := schema.Properties[name]; !known {
					return "additional_property:" + where + "." + name
				}
			}
		}
	case "array":
		arr, ok := value.([]interface{})
		if !ok {
			return "wrong_type:" + where
		}
		if schema.Items != nil {
			for i, item := range arr {
				if violation := s.checkValue(*schema.Items, item, where+"["+strconv.Itoa(i)+"]"); violation != "" {
					return violation
				}
			}
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			return "wrong_type:" + where
		}
		if schema.Pattern != "" {
			if re, ok := s.patterns[schema.Pattern]; ok && !re.MatchString(str) {
				return "pattern_mismatch:" + where
			}
		}
		if schema.MinLength != nil && len(str) < *schema.MinLength {
			return "too_short:" + where
		}
		if schema.MaxLength != nil && len(str) > *schema.MaxLength {
			return "too_long:" + where
		}
	case "integer":
		n, ok := value.(float64)
		if !ok || n != float64(int64(n)) {
			return "wrong_type:" + where
		}
		if violation := checkNumericBounds(schema, n, where); violation != "" {
			return violation
		}
	case "number":
		n, ok := value.(float64)
		if !ok {
			return "wrong_type:" + where
		}
		if violation := checkNumericBounds(schema, n, where); violation != "" {
			return violation
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return "wrong_type:" + where
		}
	}
	return ""
}

// additionalForbidden reports whether additionalProperties is
// the boolean false. Any other shape (absent, true, or a
// schema) allows additional properties.
func additionalForbidden(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err != nil {
		return false
	}
	return !flag
}

// jsonEqual compares two decoded JSON values for enum matching.
// Numbers compare numerically; everything else compares by
// canonical JSON encoding.
func jsonEqual(a, b interface{}) bool {
	af, aNum := a.(float64)
	bf, bNum := b.(float64)
	if aNum && bNum {
		return af == bf
	}
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(aj) == string(bj)
}
