package server

// Maintenance serving (Batch 7).
//
// A domain is in maintenance when the operator override is
// active or a scheduled window covers the current time. The
// page is deliberately plain: no scripts, no cookies, no
// branding, just the operator's message (or a default) and a
// Retry-After header so clients and crawlers back off. The
// middleware exempts all /_bProxy/ paths, so the control
// plane and challenge verification keep working.

import (
	"fmt"
	"html"
	"net/http"
	"time"

	"sonushield/core/domains"
	"sonushield/core/maintenance"
)

// maintenanceActive reports whether maintenance is in
// effect for the domain right now, and the message to show.
// The operator override wins over scheduled windows.
func maintenanceActive(domainName string, settings domains.DomainSettings) (bool, string) {
	now := time.Now()
	if active, message := maintenance.Active(domainName, now); active {
		return true, message
	}
	return domains.MaintenanceActiveAt(settings.MaintenanceWindows, now)
}

// serveMaintenancePage answers with a 503 and a plain
// maintenance page. The message is HTML-escaped: it comes
// from operator configuration or an API call, and must never
// break out of the page.
func serveMaintenancePage(writer http.ResponseWriter, message string) {
	if message == "" {
		message = "This site is under maintenance. Please try again shortly."
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Retry-After", "60")
	writer.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(writer, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Maintenance</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#222;background:#fff;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}main{max-width:34em;padding:2em;text-align:center}h1{font-size:1.25em;font-weight:600;margin:0 0 .5em}p{margin:0;line-height:1.5;color:#555}</style>
</head>
<body>
<main>
<h1>Under maintenance</h1>
<p>%s</p>
</main>
</body>
</html>
`, html.EscapeString(message))
}
