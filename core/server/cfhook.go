package server

import (
	"sonushield/core/cfguard"
	"sonushield/core/domains"
)

// cfguardReport feeds one monitor tick's attack state for a
// domain to the Cloudflare auto-UAM state machine (Batch
// 3). It runs at the end of checkAttack, under the firewall
// mutex, so it must never block: building Settings is a
// config scan, and cfguard.Report only starts a goroutine
// on transitions.
//
// attacking stays true through the post-attack cooldown,
// matching the attack_start/attack_end alert semantics: the
// Cloudflare level is restored only once the cooldown
// expires, so a flapping attack cannot toggle the setting
// every second.
func cfguardReport(domainName string, domainData domains.DomainData) {
	if domains.Config == nil {
		return
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name != domainName || !domain.CloudflareAutoUAM {
			continue
		}
		attacking := domainData.BypassAttack || domainData.RawAttack || domainData.BufferCooldown > 0
		cfguard.Report(domainName, attacking, cfguard.Settings{
			Enabled:      true,
			Token:        domain.CloudflareAPIToken,
			ZoneID:       domain.CloudflareZoneID,
			APIBase:      domain.CloudflareAPIBase,
			RestoreLevel: domain.CloudflareRestoreLevel,
		})
		return
	}
}

// cfguardAutoUAMEnabled reports whether auto-UAM is
// configured for a domain, for the read-only features
// response. Credentials are never exposed.
func cfguardAutoUAMEnabled(domainName string) bool {
	if domains.Config == nil {
		return false
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name == domainName {
			return domain.CloudflareAutoUAM
		}
	}
	return false
}
