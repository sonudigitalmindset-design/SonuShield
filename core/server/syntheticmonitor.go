package server

// Synthetic check loop (Batch 8).
//
// Started once from Serve; inert unless
// proxy.synthetic.enabled is true with at least one check.
// The loop reads the live configuration on every pass, so
// enabling checks via a reload starts them without a
// restart. Checks run on the configured interval (default 5
// minutes, minimum 1 minute).
//
// Alerts reuse the existing notice channels via
// utils.SendNotice, using the first configured domain's alert
// settings. When no domain configures an alert channel,
// alerts go nowhere — the status API still reports
// everything. Checks are ordinary requests through the proxy
// and never touch attack statistics.

import (
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/pnc"
	"sonushield/core/synthetic"
	"sonushield/core/utils"
)

var syntheticOnce sync.Once

// StartSyntheticChecks starts the check loop exactly once.
// It is called from Serve, after config.Load has run.
func StartSyntheticChecks() {
	syntheticOnce.Do(func() { go syntheticLoop() })
}

func syntheticLoop() {
	defer pnc.PanicHndl()
	for {
		interval := syntheticInterval()
		if interval <= 0 {
			time.Sleep(time.Minute)
			continue
		}
		syntheticRunOnce()
		time.Sleep(interval)
	}
}

// syntheticInterval returns the live check interval, or 0
// when checks are disabled or unconfigured.
func syntheticInterval() time.Duration {
	if domains.Config == nil {
		return 0
	}
	cfg := domains.Config.Proxy.Synthetic
	if !cfg.Enabled || len(cfg.Checks) == 0 {
		return 0
	}
	return cfg.SyntheticInterval()
}

func syntheticRunOnce() {
	if domains.Config == nil {
		return
	}
	cfg := domains.Config.Proxy.Synthetic
	specs := make([]synthetic.CheckSpec, 0, len(cfg.Checks))
	for _, check := range cfg.Checks {
		if check.Name == "" || check.URL == "" {
			continue
		}
		specs = append(specs, synthetic.CheckSpec{
			Name:               check.Name,
			URL:                check.URL,
			Method:             check.Method,
			ExpectStatus:       check.ExpectStatus,
			ExpectBodyContains: check.ExpectBodyContains,
		})
	}
	if len(specs) == 0 {
		return
	}
	for _, event := range synthetic.RunOnce(specs, cfg.LatencyThresholdMs) {
		switch event.Kind {
		case "failure":
			utils.SendNotice(firstDomainSettings(), "Synthetic check failed: "+event.Name, "The check \""+event.Name+"\" failed: "+event.Detail+".")
		case "recovery":
			utils.SendNotice(firstDomainSettings(), "Synthetic check recovered: "+event.Name, "The check \""+event.Name+"\" is passing again: "+event.Detail+".")
		case "latency":
			utils.SendNotice(firstDomainSettings(), "Synthetic check slow: "+event.Name, "The check \""+event.Name+"\" breached its latency threshold: "+event.Detail+".")
		case "latency_recovery":
			utils.SendNotice(firstDomainSettings(), "Synthetic check latency recovered: "+event.Name, "The check \""+event.Name+"\" latency is back under threshold: "+event.Detail+".")
		}
	}
}
