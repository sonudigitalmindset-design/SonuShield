package server

// API protection gate (Batch 4): JWT validation, API-key rate
// limits, and GraphQL depth/complexity limits.
//
// The gate runs after the normal challenge flow and just before
// the request reaches the backend, so API clients must still
// pass the usual checks (rate limits, WAF, firewall rules).
// Everything here is inert unless the operator configures it:
// no protected paths, no API-key paths, and no GraphQL path
// means no request is ever touched.
//
// Rejections are plain status codes with a short message, logged
// as block events with actions api_jwt / api_key / api_graphql
// and counted under the "api" metrics reason. Tokens and keys
// are never logged.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/logging"
	"sonushield/core/metrics"
	"strings"
)

const maxGraphQLBody = 1 << 20 // 1 MB

// checkAPIGate enforces API protection for one request. It
// returns true when the request was rejected and the caller must
// stop, false when the request may proceed.
func checkAPIGate(writer http.ResponseWriter, request *http.Request, domainName, ip string, settings domains.DomainSettings, tlsFp, ja4Fp, httpFp, browser, botFp string, stage int, susLv int) bool {
	path := request.URL.Path

	if matchesAnyPrefix(path, settings.JWTProtectedPaths) {
		if settings.JWT == nil || !validBearerToken(request, settings.JWT) {
			logAPIBlock(domainName, ip, "api_jwt", tlsFp, ja4Fp, httpFp, browser, botFp, stage, susLv, request)
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Unauthorized"))
			return true
		}
	}

	if matchesAnyPrefix(path, settings.APIKeyPaths) {
		// A nil APIKeys state (paths configured, no keys) fails
		// closed: Check on a nil state reports unknown.
		allowed, known := settings.APIKeys.Check(request.Header.Get(settings.APIKeyHeader))
		if !known {
			logAPIBlock(domainName, ip, "api_key", tlsFp, ja4Fp, httpFp, browser, botFp, stage, susLv, request)
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Unauthorized"))
			return true
		}
		if !allowed {
			logAPIBlock(domainName, ip, "api_key", tlsFp, ja4Fp, httpFp, browser, botFp, stage, susLv, request)
			writer.Header().Set("Content-Type", "text/plain")
			writer.Header().Set("Retry-After", "60")
			writer.WriteHeader(http.StatusTooManyRequests)
			writer.Write([]byte("Too Many Requests"))
			return true
		}
	}

	if settings.GraphQLPath != "" && path == settings.GraphQLPath && request.Method == http.MethodPost && !isUpgradeRequest(request) {
		if checkGraphQLLimits(writer, request, settings) {
			logAPIBlock(domainName, ip, "api_graphql", tlsFp, ja4Fp, httpFp, browser, botFp, stage, susLv, request)
			return true
		}
	}

	return false
}

func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func validBearerToken(request *http.Request, verifier *domains.JWTVerifier) bool {
	auth := request.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	return verifier.Verify(strings.TrimSpace(auth[len("Bearer "):]))
}

// checkGraphQLLimits reads a JSON GraphQL request body, checks
// the query against the configured depth/field limits, and
// restores the body for the backend. It returns true when the
// request was rejected. Non-JSON bodies, bodies without a
// "query" string, and bodies over the read cap are passed
// through untouched for the backend to handle.
func checkGraphQLLimits(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings) bool {
	if settings.GraphQLMaxDepth <= 0 && settings.GraphQLMaxFields <= 0 {
		return false
	}
	contentType := request.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return false
	}
	if request.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxGraphQLBody+1))
	if err != nil {
		restoreBody(request, nil)
		return false
	}
	restoreBody(request, body)
	if len(body) > maxGraphQLBody {
		return false
	}
	var payload struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Query == "" {
		return false
	}
	depth, fields := domains.AnalyzeGraphQLQuery(payload.Query)
	if (settings.GraphQLMaxDepth > 0 && depth > settings.GraphQLMaxDepth) || (settings.GraphQLMaxFields > 0 && fields > settings.GraphQLMaxFields) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("GraphQL query exceeds configured limits"))
		return true
	}
	return false
}

func restoreBody(request *http.Request, body []byte) {
	if body == nil {
		body = []byte{}
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}

func logAPIBlock(domainName, ip, action string, tlsFp, ja4Fp, httpFp, browser, botFp string, stage, susLv int, request *http.Request) {
	metrics.ObserveBlock(domainName, "api")
	logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: action, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: stage, SusLevel: susLv, Method: request.Method, Path: request.URL.Path, UserAgent: request.UserAgent()})
}
