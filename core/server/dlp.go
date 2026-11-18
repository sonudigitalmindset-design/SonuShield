package server

// DLP response scanning (Batch 8).
//
// Runs in the ModifyResponse hook before the edge-cache store,
// so cached copies carry redacted bytes. Only 2xx responses
// with text-ish content types and no Content-Encoding are
// scanned, up to the configured cap; everything else passes
// through unscanned. Redaction substitutes "[redacted]" for
// each match and drops ETag/Content-MD5; block mode replaces
// the whole response with a generic 403. Log entries carry
// pattern names and counts only — matched content is never
// logged. With no scanner configured this is a no-op.

import (
	"bytes"
	"io"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/logging"
	"strconv"
	"strings"
)

// applyDLP scans one backend response and applies the DLP
// action. It never returns an error and never leaves a
// response damaged: any failure restores the original bytes.
func applyDLP(resp *http.Response, settings domains.DomainSettings) {
	scanner := settings.DLP
	if scanner == nil || resp == nil || resp.Body == nil {
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.StatusCode == http.StatusNoContent {
		return
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return
	}
	if !compressibleContentType(resp.Header.Get("Content-Type")) {
		return
	}
	body, ok := readCappedBody(resp, scanner.MaxBytes())
	if !ok {
		// Oversized or read error: restore and skip scanning
		// (fail open, documented).
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return
	}
	if len(body) == 0 {
		restoreResponseBody(resp, body)
		return
	}
	result := scanner.Scan(body)
	if result.Matches == 0 {
		restoreResponseBody(resp, body)
		return
	}
	domainName := ""
	method, path, ip := "", "", ""
	if resp.Request != nil {
		domainName = resp.Request.Host
		method = resp.Request.Method
		path = resp.Request.URL.Path
		ip = resp.Request.Header.Get("x-real-ip")
	}
	if scanner.BlockMode() {
		scanner.NoteBlocked()
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "dlp_block", Rule: strings.Join(result.Matched, ","), Method: method, Path: path})
		blocked := []byte("Forbidden.")
		restoreResponseBody(resp, blocked)
		resp.StatusCode = http.StatusForbidden
		resp.Status = "403 Forbidden"
		resp.ContentLength = int64(len(blocked))
		resp.Header.Set("Content-Length", strconv.Itoa(len(blocked)))
		resp.Header.Set("Content-Type", "text/plain")
		resp.Header.Del("Content-MD5")
		resp.Header.Del("ETag")
		return
	}
	scanner.NoteRedacted()
	logging.Log(logging.Entry{Event: "dlp", Domain: domainName, IP: ip, Action: "dlp_redact", Rule: strings.Join(result.Matched, ","), Method: method, Path: path})
	restoreResponseBody(resp, result.Body)
	resp.ContentLength = int64(len(result.Body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(result.Body)))
	resp.Header.Del("Content-MD5")
	resp.Header.Del("ETag")
}
