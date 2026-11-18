package anomaly

// Process-wide detector used by the proxy server. The
// server package enables/disables it from
// proxy.anomalyDetection at startup and on reload, calls
// Observe from the request path, and calls Tick from the
// monitor loop. All three are safe for concurrent use and
// no-ops while disabled.

var defaultDetector = New()

// SetEnabled turns the process-wide detector on or off,
// discarding accumulated state either way.
func SetEnabled(v bool) { defaultDetector.SetEnabled(v) }

// Enabled reports whether the process-wide detector is on.
func Enabled() bool { return defaultDetector.Enabled() }

// Observe records one evaluated request on the
// process-wide detector and returns anomalies from any
// window the observation completed. See
// Detector.Observe.
func Observe(domain, ip, path, ua, fp string, risk int, challenged bool) []Anomaly {
	return defaultDetector.Observe(domain, ip, path, ua, fp, risk, challenged)
}

// Tick scores completed windows on the process-wide
// detector. See Detector.Tick.
func Tick() []Anomaly { return defaultDetector.Tick() }
