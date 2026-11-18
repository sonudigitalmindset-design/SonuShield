package server

// BGP announcement monitoring loop (Batch 8).
//
// Started once from Serve; inert unless
// proxy.bgpMonitor.enabled is true with at least one prefix
// and one expected origin. The loop reads the live
// configuration on every pass, so enabling monitoring via a
// reload starts it without a restart. Checks run on the
// configured interval (default hourly, minimum 5 minutes:
// RIPEstat aggregates in multi-hour intervals, so checking
// more often adds nothing).
//
// Alerts reuse the existing notice channels via
// utils.SendNotice, using the first configured domain's alert
// settings. When no domain configures an alert channel,
// alerts go nowhere — the status API still reports
// everything. Monitoring is fail-open and advisory only: a
// failed fetch raises no alert and never affects traffic.

import (
	"sync"
	"time"

	"sonushield/core/bgp"
	"sonushield/core/domains"
	"sonushield/core/pnc"
	"sonushield/core/utils"
)

var bgpMonitorOnce sync.Once

// StartBGPMonitor starts the monitoring loop exactly once.
// It is called from Serve, after config.Load has run.
func StartBGPMonitor() {
	bgpMonitorOnce.Do(func() { go bgpMonitorLoop() })
}

func bgpMonitorLoop() {
	defer pnc.PanicHndl()
	for {
		interval := bgpCheckInterval()
		if interval <= 0 {
			// Disabled: re-check every minute in case a reload
			// enables it.
			time.Sleep(time.Minute)
			continue
		}
		bgpCheckOnce()
		time.Sleep(interval)
	}
}

// bgpCheckInterval returns the live check interval, or 0 when
// monitoring is disabled or unconfigured.
func bgpCheckInterval() time.Duration {
	if domains.Config == nil {
		return 0
	}
	monitor := domains.Config.Proxy.BGPMonitor
	if !monitor.Enabled || len(monitor.Prefixes) == 0 || len(monitor.ExpectedOrigins) == 0 {
		return 0
	}
	return monitor.BGPCheckInterval()
}

func bgpCheckOnce() {
	if domains.Config == nil {
		return
	}
	monitor := domains.Config.Proxy.BGPMonitor
	events := bgp.Check(monitor.Prefixes, monitor.ExpectedOrigins, monitor.BGPAPIBase(), monitor.APIToken, monitor.BGPSource(), bgp.FetchOrigins)
	for _, event := range events {
		if event.Unexpected {
			utils.SendNotice(firstDomainSettings(),
				"BGP alert: unexpected origin for "+event.Prefix,
				"The prefix "+event.Prefix+" is now seen as "+event.Detail+", which does not match the expected origins. This may indicate a route hijack or a misconfiguration at the data source. Check the prefix in your BGP monitoring tool before acting.")
		} else {
			utils.SendNotice(firstDomainSettings(),
				"BGP recovery: "+event.Prefix+" back to expected origins",
				"The prefix "+event.Prefix+" is now seen as "+event.Detail+", matching the expected origins.")
		}
	}
}
