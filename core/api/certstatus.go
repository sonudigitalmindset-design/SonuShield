package api

// Certificate + subdomain status APIs (Batch 7).
//
// GET_CERT_STATUS reports the expiry state of every
// configured certificate file, read live, plus whether
// expiry alerting is enabled and when each certificate was
// last alerted on. It works whether or not alerting is
// enabled: the file reads are the same ones the grade scan
// performs.
//
// GET_SUBDOMAIN_STATUS reports the monitoring configuration
// and the last recorded DNS state for every monitored name.
// Names that have never been observed yet (monitoring
// disabled, or the first check has not run) appear with no
// recorded state. No CT-log data is involved: only the
// operator-supplied names, resolved via the system resolver.

import (
	"time"

	"sonushield/core/certmon"
	"sonushield/core/domains"
)

// certStatusResponse builds the GET_CERT_STATUS response.
// No parameters are accepted.
func certStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	cfg := domains.Config
	if cfg == nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}
	alertDays := cfg.Proxy.CertAlertDays
	if alertDays <= 0 {
		alertDays = 14
	}
	now := time.Now()
	entries := []map[string]interface{}{}
	for _, domain := range cfg.Domains {
		entry := map[string]interface{}{
			"DOMAIN": domain.Name,
		}
		if cfg.Proxy.Cloudflare {
			entry["STATUS"] = "skipped_cloudflare"
			entry["NOTE"] = "TLS terminates upstream in Cloudflare mode"
			entries = append(entries, entry)
			continue
		}
		if domain.Certificate == "" {
			entry["STATUS"] = "none"
			entry["NOTE"] = "no certificate file configured (autoSSL may provide one)"
			entries = append(entries, entry)
			continue
		}
		cert, err := certmon.ReadLeafCert(domain.Certificate)
		if err != nil {
			entry["STATUS"] = "unreadable"
			entry["ERROR"] = err.Error()
			entries = append(entries, entry)
			continue
		}
		days := certmon.DaysRemaining(cert, now)
		entry["EXPIRES"] = cert.NotAfter.Format(time.RFC3339)
		entry["DAYS_REMAINING"] = days
		switch {
		case days < 0:
			entry["STATUS"] = "expired"
		case days <= alertDays:
			entry["STATUS"] = "expiring"
		default:
			entry["STATUS"] = "ok"
		}
		if last, ok := certmon.LastCertAlert(domain.Certificate); ok {
			entry["LAST_ALERT"] = last.Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}
	return map[string]interface{}{
		"ENABLED":    cfg.Proxy.CertAlerts,
		"ALERT_DAYS": alertDays,
		"DOMAINS":    entries,
	}, ""
}

// subdomainStatusResponse builds the GET_SUBDOMAIN_STATUS
// response. No parameters are accepted.
func subdomainStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	cfg := domains.Config
	if cfg == nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}
	monitor := cfg.Proxy.SubdomainMonitor
	enabled := monitor != nil && monitor.Enabled
	interval := 60
	threshold := 3
	configured := []string{}
	if monitor != nil {
		configured = monitor.Domains
		if monitor.IntervalMinutes > 0 {
			interval = monitor.IntervalMinutes
			if interval < 5 {
				interval = 5
			}
		}
		if monitor.FailureThreshold > 0 {
			threshold = monitor.FailureThreshold
		}
	}
	recorded := map[string]certmon.SubdomainStatus{}
	for _, status := range certmon.SubdomainStatuses() {
		recorded[status.Name] = status
	}
	entries := []map[string]interface{}{}
	for _, name := range configured {
		entry := map[string]interface{}{"NAME": name}
		if status, ok := recorded[name]; ok {
			entry["ADDRESSES"] = status.Addresses
			entry["BASELINE_SET"] = status.BaselineSet
			entry["LAST_CHECKED"] = status.LastChecked.Format(time.RFC3339)
			entry["CONSECUTIVE_FAILURES"] = status.ConsecutiveFailures
			if status.LastError != "" {
				entry["LAST_ERROR"] = status.LastError
			}
			if !status.LastChangeAlert.IsZero() {
				entry["LAST_CHANGE_ALERT"] = status.LastChangeAlert.Format(time.RFC3339)
			}
		} else {
			entry["ADDRESSES"] = []string{}
			entry["BASELINE_SET"] = false
			entry["NOTE"] = "not yet observed"
		}
		entries = append(entries, entry)
	}
	return map[string]interface{}{
		"ENABLED":           enabled,
		"INTERVAL_MINUTES":  interval,
		"FAILURE_THRESHOLD": threshold,
		"DOMAINS":           entries,
	}, ""
}
