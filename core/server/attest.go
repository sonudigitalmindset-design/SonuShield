package server

// Mobile app attestation gate (Batch 8).
//
// Runs after the API-protection gate and before proxying: a
// request to an attested path must carry a valid attestation
// token in the configured header. In block mode (the default)
// an unverified request is answered with a generic 403 and
// never reaches the backend; in log mode the failure is logged
// and the request continues. The token is never logged. With
// attestation unconfigured the check is a no-op.

import (
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/logging"
	"sonushield/core/metrics"
)

// checkAttestation enforces attestation for one request. It
// returns true when the request was rejected and the caller
// must stop, false when the request may proceed.
func checkAttestation(writer http.ResponseWriter, request *http.Request, domainName, ip string, settings domains.DomainSettings, tlsFp, ja4Fp, httpFp, browser, botFp string, stage, susLv int, logPath string) bool {
	if settings.Attest == nil || !settings.Attest.Required(request.URL.Path) {
		return false
	}
	if settings.Attest.Verify(request.Header.Get(settings.Attest.HeaderName())) {
		return false
	}
	logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "attestation", Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: stage, SusLevel: susLv, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
	if settings.Attest.LogOnly() {
		return false
	}
	metrics.ObserveBlock(domainName, "attestation")
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusForbidden)
	writer.Write([]byte("Forbidden."))
	return true
}
