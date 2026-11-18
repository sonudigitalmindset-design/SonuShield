package server

import (
	"sonushield/core/anomaly"
	"sonushield/core/domains"
	"sonushield/core/logging"
)

// applyAnomalyConfig (re)configures the process-wide
// experimental anomaly detector (Batch 3) from the live
// configuration. It runs once at startup (from Serve) and
// after every validated reload (from reloadFromConfig), so
// enabling or disabling proxy.anomalyDetection takes
// effect without a restart. Toggling either way discards
// accumulated window state. The detector is log-only: it
// never changes suspicion levels, challenges, or blocks.
// See core/anomaly and docs/ml-evaluation.md.
func applyAnomalyConfig() {
	anomaly.SetEnabled(domains.Config != nil && domains.Config.Proxy.AnomalyDetection)
}

// anomalyObserve records one evaluated request with the
// anomaly detector and logs any anomalies from a window
// the observation completed. It is called from Middleware
// after firewall rules, reputation, and threat-sharing
// evaluation, so every request that reaches the challenge
// flow is observed; early-blocked requests (rate limits,
// blocklists) are not. challenged reports whether the
// request arrived without a challenge cookie. No-op while
// the detector is disabled.
func anomalyObserve(domainName, ip, path, ua, fp string, risk int, challenged bool) {
	if !anomaly.Enabled() {
		return
	}
	logAnomalies(anomaly.Observe(domainName, ip, path, ua, fp, risk, challenged))
}

// anomalyTick scores windows completed since the last
// tick, so quiet periods still close windows. It is called
// from the one-second monitor loop. No-op while the
// detector is disabled.
func anomalyTick() {
	if !anomaly.Enabled() {
		return
	}
	logAnomalies(anomaly.Tick())
}

// logAnomalies writes one structured-log entry per
// anomaly: Event "anomaly", Action "anomaly_signal", the
// detector score in AnomalyScore. Like every other
// structured entry, these flow through logging.Log, so
// privacy mode and log rotation apply unchanged.
func logAnomalies(found []anomaly.Anomaly) {
	for _, a := range found {
		logging.Log(logging.Entry{Event: "anomaly", Domain: a.Domain, IP: a.IP, Action: "anomaly_signal", AnomalyScore: a.Score})
	}
}
