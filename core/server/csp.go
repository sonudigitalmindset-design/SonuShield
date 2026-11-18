package server

// CSP report collection endpoint (Batch 8).
//
// POST /_bProxy/csp-report receives Content Security Policy
// violation reports from browsers. The operator points the
// site's report-uri / report-to directive at this path. The
// endpoint is handled before the challenge flow — browsers
// deliver reports without cookies or authentication — and
// always answers 204 for a parseable report, 400 for a body
// that is not a report at all. Both wire shapes are accepted:
//
//   - Legacy: application/csp-report with a single object
//     {"csp-report": {document-uri, blocked-uri, ...}}.
//   - Reporting API: application/reports+json (or JSON) with
//     an array of {type, body} entries; only "csp-violation"
//     entries are kept.
//
// Bodies are capped at 64 KiB. Query strings are stripped
// from stored URIs. Reports never influence enforcement.

import (
	"encoding/json"
	"io"
	"net/http"
	"sonushield/core/csp"
	"strings"
	"time"
)

const maxCSPReportBytes = 64 << 10

// cspReportBody is the wire shape of one report body, in
// either format. Only the stored subset of fields is decoded.
// The legacy report-uri format uses kebab-case field names
// ("document-uri", "violated-directive", ...); the Reporting
// API (report-to) format uses camelCase ("documentURL",
// "violatedDirective", ...). Both spellings are accepted:
// kebab-case wins when both are present.
type cspReportBody struct {
	DocumentURI        string `json:"document-uri"`
	BlockedURI         string `json:"blocked-uri"`
	ViolatedDirective  string `json:"violated-directive"`
	EffectiveDirective string `json:"effective-directive"`
	SourceFile         string `json:"source-file"`
	LineNumber         int    `json:"line-number"`
	ColumnNumber       int    `json:"column-number"`
	StatusCode         int    `json:"status-code"`
	Disposition        string `json:"disposition"`
}

// cspReportBodyCamel is the Reporting API spelling of the same
// fields. It exists only for decoding; see UnmarshalJSON.
type cspReportBodyCamel struct {
	DocumentURI        string `json:"documentURL"`
	BlockedURI         string `json:"blockedURL"`
	ViolatedDirective  string `json:"violatedDirective"`
	EffectiveDirective string `json:"effectiveDirective"`
	SourceFile         string `json:"sourceFile"`
	LineNumber         int    `json:"lineNumber"`
	ColumnNumber       int    `json:"columnNumber"`
	StatusCode         int    `json:"statusCode"`
	Disposition        string `json:"disposition"`
}

// UnmarshalJSON decodes either field spelling, preferring the
// kebab-case value when both spellings carry a field.
func (b *cspReportBody) UnmarshalJSON(data []byte) error {
	type kebab cspReportBody
	var k kebab
	if err := json.Unmarshal(data, &k); err != nil {
		return err
	}
	var c cspReportBodyCamel
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	*b = cspReportBody(k)
	if b.DocumentURI == "" {
		b.DocumentURI = c.DocumentURI
	}
	if b.BlockedURI == "" {
		b.BlockedURI = c.BlockedURI
	}
	if b.ViolatedDirective == "" {
		b.ViolatedDirective = c.ViolatedDirective
	}
	if b.EffectiveDirective == "" {
		b.EffectiveDirective = c.EffectiveDirective
	}
	if b.SourceFile == "" {
		b.SourceFile = c.SourceFile
	}
	if b.LineNumber == 0 {
		b.LineNumber = c.LineNumber
	}
	if b.ColumnNumber == 0 {
		b.ColumnNumber = c.ColumnNumber
	}
	if b.StatusCode == 0 {
		b.StatusCode = c.StatusCode
	}
	if b.Disposition == "" {
		b.Disposition = c.Disposition
	}
	return nil
}

// stripURIQuery removes the query string and fragment from a
// URI, matching the logging policy for stored paths.
func stripURIQuery(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		return uri[:i]
	}
	return uri
}

func toCSPReport(body cspReportBody) csp.Report {
	return csp.Report{
		Time:               time.Now().UTC(),
		DocumentURI:        stripURIQuery(body.DocumentURI),
		BlockedURI:         stripURIQuery(body.BlockedURI),
		ViolatedDirective:  body.ViolatedDirective,
		EffectiveDirective: body.EffectiveDirective,
		SourceFile:         stripURIQuery(body.SourceFile),
		LineNumber:         body.LineNumber,
		ColumnNumber:       body.ColumnNumber,
		StatusCode:         body.StatusCode,
		Disposition:        body.Disposition,
	}
}

// HandleCSPReport answers POST /_bProxy/csp-report. It
// reports whether it handled the request: false for any other
// path, true (with a written response) for this path.
func HandleCSPReport(writer http.ResponseWriter, request *http.Request, domainName string) bool {
	if request.URL.Path != "/_bProxy/csp-report" {
		return false
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		writer.Write([]byte("404 Not Found"))
		return true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxCSPReportBytes+1))
	if err != nil || int64(len(body)) > maxCSPReportBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	stored := 0
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/csp-report") {
		var envelope struct {
			Report cspReportBody `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &envelope); err == nil && envelope.Report.ViolatedDirective != "" {
			csp.Record(domainName, toCSPReport(envelope.Report))
			stored++
		}
	} else {
		// Reporting API shape: an array of entries. A single
		// object with a "body" is also accepted, leniently.
		var entries []struct {
			Type string        `json:"type"`
			Body cspReportBody `json:"body"`
		}
		if err := json.Unmarshal(body, &entries); err == nil {
			for _, entry := range entries {
				if entry.Type != "" && entry.Type != "csp-violation" {
					continue
				}
				if entry.Body.ViolatedDirective == "" {
					continue
				}
				csp.Record(domainName, toCSPReport(entry.Body))
				stored++
			}
		} else {
			var single struct {
				Body cspReportBody `json:"body"`
			}
			if err := json.Unmarshal(body, &single); err == nil && single.Body.ViolatedDirective != "" {
				csp.Record(domainName, toCSPReport(single.Body))
				stored++
			}
		}
	}
	if stored == 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}
