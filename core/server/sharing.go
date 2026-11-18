package server

// Threat-sharing peer endpoint (Batch 8).
//
// GET/POST /_bProxy/threat-sharing/indicators exchanges
// indicators with explicitly peered SonuShield instances.
// Every request must carry a valid X-SonuShield-Sharing HMAC
// signature (see core/sharing). The endpoint is handled before
// the challenge flow — peers are machines, not browsers — and
// does not exist at all while sharing is disabled: requests
// then fall through to the origin like any unknown path.

import (
	"encoding/json"
	"io"
	"net/http"
	"sonushield/core/sharing"
	"time"
)

const maxSharingBody = 1 << 20

// HandleSharing answers the peer endpoint. It reports whether
// it handled the request.
func HandleSharing(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.Path != "/_bProxy/threat-sharing/indicators" {
		return false
	}
	if !sharing.Enabled() {
		return false
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		writer.Write([]byte("404 Not Found"))
		return true
	}
	var body []byte
	if request.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(io.LimitReader(request.Body, maxSharingBody+1))
		if err != nil || int64(len(body)) > maxSharingBody {
			writer.WriteHeader(http.StatusBadRequest)
			return true
		}
	}
	peer, ok := sharing.Verify(request.Header.Get("X-SonuShield-Sharing"), request.Method, request.URL.Path, body, time.Now().UTC())
	if !ok {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Unauthorized"))
		return true
	}
	if request.Method == http.MethodGet {
		payload, err := json.Marshal(sharing.LocalIndicators())
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return true
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Write(payload)
		return true
	}
	var inds []sharing.Indicator
	if err := json.Unmarshal(body, &inds); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	sharing.Receive(peer.Name, inds)
	writer.WriteHeader(http.StatusNoContent)
	return true
}
