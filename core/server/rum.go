package server

// RUM beacon endpoint + snippet (Batch 8).
//
// POST /_bProxy/rum accepts real-user timing beacons from
// the snippet served at GET /_bProxy/rum.js. Both are handled
// before the challenge flow — beacons come from ordinary page
// loads, not from challenged clients — and neither requires
// authentication: beacons carry timing buckets only, no
// identity, and worst-case abuse pollutes aggregate counters
// that the operator can ignore.
//
// The snippet is served ONLY at /_bProxy/rum.js. It is never
// injected into origin content and is not added to challenge
// pages: the operator embeds it on origin pages with
// <script src="/_bProxy/rum.js" async></script>. The snippet
// reads PerformanceNavigationTiming once per page load and
// sends one beacon; it sends nothing when the timing API is
// unavailable, and never sends URLs with query strings (the
// path is taken from location.pathname only).

import (
	"encoding/json"
	"io"
	"net/http"
	"sonushield/core/privacy"
	"sonushield/core/rum"
	"strings"
)

const maxRUMBeaconBytes = 4 << 10

// rumSnippet is the operator-embedded beacon script. It uses
// only PerformanceNavigationTiming, sends one beacon per
// page load via sendBeacon (fetch fallback), and includes no
// identifiers, URLs, or query strings.
const rumSnippet = `(function(){try{var t=performance.getEntriesByType("navigation")[0];if(!t)return;var b={dns:Math.round(t.domainLookupEnd-t.domainLookupStart),connect:Math.round(t.connectEnd-t.connectStart),tls:t.secureConnectionStart?Math.round(t.connectEnd-t.secureConnectionStart):-1,ttfb:Math.round(t.responseStart-t.requestStart),dom:Math.round(t.domContentLoadedEventEnd-t.responseEnd),load:Math.round(t.loadEventEnd-t.responseEnd),path:location.pathname};var s=JSON.stringify(b);if(navigator.sendBeacon){navigator.sendBeacon("/_bProxy/rum",s);}else{fetch("/_bProxy/rum",{method:"POST",headers:{"Content-Type":"application/json"},body:s,keepalive:true});}}catch(e){}})();`

// HandleRUM answers the beacon endpoint and the snippet.
// It reports whether it handled the request.
func HandleRUM(writer http.ResponseWriter, request *http.Request, domainName string) bool {
	switch request.URL.Path {
	case "/_bProxy/rum.js":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusNotFound)
			writer.Write([]byte("404 Not Found"))
			return true
		}
		writer.Header().Set("Content-Type", "application/javascript")
		writer.Header().Set("Cache-Control", "public, max-age=3600")
		writer.Write([]byte(rumSnippet))
		return true
	case "/_bProxy/rum":
		if request.Method != http.MethodPost {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusNotFound)
			writer.Write([]byte("404 Not Found"))
			return true
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maxRUMBeaconBytes+1))
		if err == nil && int64(len(body)) <= maxRUMBeaconBytes {
			recordRUMBeacon(body, domainName)
		}
		// Always 204: beacon delivery must never surface an
		// error to the page, and validation failures reveal
		// nothing either way.
		writer.WriteHeader(http.StatusNoContent)
		return true
	default:
		return false
	}
}

func recordRUMBeacon(body []byte, domainName string) {
	var payload struct {
		DNS     *int64 `json:"dns"`
		Connect *int64 `json:"connect"`
		TLS     *int64 `json:"tls"`
		TTFB    *int64 `json:"ttfb"`
		DOM     *int64 `json:"dom"`
		Load    *int64 `json:"load"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return
	}
	raw := map[string]int64{}
	if payload.DNS != nil {
		raw["dns"] = *payload.DNS
	}
	if payload.Connect != nil {
		raw["connect"] = *payload.Connect
	}
	if payload.TLS != nil {
		raw["tls"] = *payload.TLS
	}
	if payload.TTFB != nil {
		raw["ttfb"] = *payload.TTFB
	}
	if payload.DOM != nil {
		raw["dom"] = *payload.DOM
	}
	if payload.Load != nil {
		raw["load"] = *payload.Load
	}
	path := stripURIQuery(payload.Path)
	if !strings.HasPrefix(path, "/") || len(path) > 256 {
		path = ""
	}
	rum.Record(domainName, rum.NewBeacon(raw, path), privacy.Enabled())
}
