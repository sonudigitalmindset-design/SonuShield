package server

// Certificate + subdomain monitoring loop (Batch 7).
//
// Started once from Serve; inert unless the operator enables
// proxy.certAlerts or proxy.subdomainMonitor. The loop reads
// the live configuration on every pass, so enabling either
// feature via a reload starts monitoring without a restart.
//
// Certificate checks run hourly over the certificate files
// named in the configuration (Cloudflare mode and
// autoSSL-managed cert-less domains are skipped: the former
// terminate elsewhere, the latter renew automatically).
// Expiry alerts are deduplicated to one per certificate per
// day by the certmon package.
//
// Subdomain checks resolve operator-supplied names on the
// configured interval. The first successful resolution is a
// silent baseline; later address-set changes and N
// consecutive failures alert. DNS failures never affect
// traffic: monitoring is fail-open and advisory only.
//
// Alerts reuse the existing notice channels via
// utils.SendNotice, using the first configured domain's
// alert settings. When no domain configures an alert
// channel, alerts go nowhere — the status APIs still report
// everything. No CT-log lookup is performed: this build
// watches only the names the operator lists, resolved via
// the system DNS resolver.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"sonushield/core/certmon"
	"sonushield/core/domains"
	"sonushield/core/pnc"
	"sonushield/core/utils"
)

var certMonitorOnce sync.Once

// StartCertMonitor starts the monitoring loop exactly once.
// It is called from Serve, after config.Load has run.
func StartCertMonitor() {
	certMonitorOnce.Do(func() { go certMonitorLoop() })
}

func certMonitorLoop() {
	defer pnc.PanicHndl()
	checkCerts()
	checkSubdomains()
	var lastCertCheck, lastSubdomainCheck time.Time
	lastCertCheck = time.Now()
	lastSubdomainCheck = time.Now()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		if now.Sub(lastCertCheck) >= time.Hour {
			lastCertCheck = now
			checkCerts()
		}
		interval := subdomainInterval()
		if interval > 0 && now.Sub(lastSubdomainCheck) >= interval {
			lastSubdomainCheck = now
			checkSubdomains()
		}
	}
}

// certAlertDays returns the live expiry threshold: the
// configured value, or 14 days when unset/invalid.
func certAlertDays() int {
	if domains.Config == nil {
		return 14
	}
	days := domains.Config.Proxy.CertAlertDays
	if days <= 0 {
		return 14
	}
	return days
}

// subdomainInterval returns the live subdomain check
// interval, or 0 when monitoring is disabled.
func subdomainInterval() time.Duration {
	if domains.Config == nil {
		return 0
	}
	monitor := domains.Config.Proxy.SubdomainMonitor
	if monitor == nil || !monitor.Enabled || len(monitor.Domains) == 0 {
		return 0
	}
	minutes := monitor.IntervalMinutes
	if minutes <= 0 {
		minutes = 60
	} else if minutes < 5 {
		minutes = 5
	}
	return time.Duration(minutes) * time.Minute
}

// subdomainFailureThreshold returns the live failure
// threshold: the configured value, or 3 when unset/invalid.
func subdomainFailureThreshold() int {
	if domains.Config == nil {
		return 3
	}
	monitor := domains.Config.Proxy.SubdomainMonitor
	if monitor == nil || monitor.FailureThreshold <= 0 {
		return 3
	}
	return monitor.FailureThreshold
}

func checkCerts() {
	defer pnc.PanicHndl()
	if domains.Config == nil || !domains.Config.Proxy.CertAlerts {
		return
	}
	now := time.Now()
	threshold := certAlertDays()
	for _, domain := range domains.Config.Domains {
		if domains.Config.Proxy.Cloudflare || domain.Certificate == "" {
			continue
		}
		cert, err := certmon.ReadLeafCert(domain.Certificate)
		if err != nil {
			// Unreadable certs are reported by the grade
			// scan and status API; alerting on every hourly
			// read failure would spam the operator.
			continue
		}
		days := certmon.DaysRemaining(cert, now)
		if days > threshold {
			continue
		}
		if !certmon.ShouldAlertCert(domain.Certificate, now) {
			continue
		}
		var title, body string
		if days < 0 {
			title = fmt.Sprintf("Certificate expired: %s", domain.Name)
			body = fmt.Sprintf("The certificate for %s expired %d day(s) ago (%s). Clients will see certificate errors until it is replaced.",
				domain.Name, -days, cert.NotAfter.Format(time.RFC3339))
		} else {
			title = fmt.Sprintf("Certificate expiring soon: %s", domain.Name)
			body = fmt.Sprintf("The certificate for %s expires in %d day(s) (%s). Renew it before expiry to avoid client errors.",
				domain.Name, days, cert.NotAfter.Format(time.RFC3339))
		}
		utils.SendNotice(firstDomainSettings(), title, body)
	}
}

func checkSubdomains() {
	defer pnc.PanicHndl()
	if domains.Config == nil {
		return
	}
	monitor := domains.Config.Proxy.SubdomainMonitor
	if monitor == nil || !monitor.Enabled {
		return
	}
	threshold := subdomainFailureThreshold()
	now := time.Now()
	for _, name := range monitor.Domains {
		if name == "" {
			continue
		}
		addrs, lookupErr := resolveName(name)
		outcome := certmon.RecordLookup(name, addrs, lookupErr, threshold, now)
		if outcome.Changed {
			utils.SendNotice(firstDomainSettings(),
				fmt.Sprintf("Subdomain address change: %s", name),
				fmt.Sprintf("DNS for %s now resolves to %s (was %s). If this change was not planned, check the DNS records.",
					name, certmon.AddressSet(addrs), certmon.AddressSet(outcome.Previous)))
		}
		if outcome.FailureAlert {
			utils.SendNotice(firstDomainSettings(),
				fmt.Sprintf("Subdomain unreachable: %s", name),
				fmt.Sprintf("DNS for %s has failed %d consecutive time(s). The name may be misconfigured or its DNS may be down; monitoring continues.",
					name, threshold))
		}
	}
}

// resolveName resolves name to string addresses, or returns
// the resolver error. Failures are advisory only: monitoring
// never blocks on DNS.
func resolveName(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses returned for %s", name)
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return addrs, nil
}

// firstDomainSettings returns the settings of an arbitrary
// configured domain, for alert-channel configuration. When
// no domain is configured, the zero value is returned and
// SendNotice is inert.
func firstDomainSettings() domains.DomainSettings {
	var settings domains.DomainSettings
	domains.DomainsMap.Range(func(_, value any) bool {
		if casted, ok := value.(domains.DomainSettings); ok {
			settings = casted
			return false
		}
		return true
	})
	return settings
}
