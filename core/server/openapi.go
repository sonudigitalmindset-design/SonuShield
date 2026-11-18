package server

// OpenAPI request validation gate (Batch 8).
//
// Runs after the attestation gate and before proxying, for
// requests under the domain's validated prefixes. The request
// body is read (up to the validation cap) and restored with
// GetBody, mirroring the GraphQL gate, so proxying and
// replay-safe retries see the original body. Violations are
// logged with the rule and field only — never body content —
// and answered with a generic 400 in block mode. In log mode
// (the default) the request continues. With no spec loaded
// this is a no-op.

import (
	"bytes"
	"io"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/logging"
	"sonushield/core/metrics"
	"strings"
)

const maxOpenAPIValidationBody = 1 << 20 // 1 MB

// checkOpenAPI enforces OpenAPI validation for one request. It
// returns true when the request was rejected and the caller
// must stop, false when the request may proceed.
func checkOpenAPI(writer http.ResponseWriter, request *http.Request, domainName, ip string, settings domains.DomainSettings, tlsFp, ja4Fp, httpFp, browser, botFp string, stage, susLv int, logPath string) bool {
	spec := settings.OpenAPI
	if spec == nil || !spec.Validated(request.URL.Path) {
		return false
	}
	var body []byte
	hasBody := false
	if request.Body != nil && request.Method != http.MethodGet && request.Method != http.MethodHead {
		raw, err := io.ReadAll(io.LimitReader(request.Body, maxOpenAPIValidationBody+1))
		if err == nil && int64(len(raw)) <= maxOpenAPIValidationBody {
			body = raw
			hasBody = len(raw) > 0
			request.Body = io.NopCloser(bytes.NewReader(raw))
			request.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(raw)), nil
			}
		} else {
			// Oversized or unreadable: restore what was read
			// plus the remainder, and treat the body as
			// unvalidatable (a violation when a schema
			// requires a body; see Validate).
			request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), request.Body))
			body = nil
			hasBody = true
		}
	}
	headers := map[string]string{}
	for name, values := range request.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	violation := spec.Validate(request.Method, request.URL.Path, request.URL.Query(), headers, body, hasBody)
	if violation == "" {
		return false
	}
	logging.Log(logging.Entry{Event: "openapi", Domain: domainName, IP: ip, Action: "openapi_violation", Rule: violation, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: stage, SusLevel: susLv, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
	if !spec.BlockMode(request.URL.Path) {
		return false
	}
	metrics.ObserveBlock(domainName, "openapi")
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusBadRequest)
	writer.Write([]byte("Bad request."))
	return true
}
