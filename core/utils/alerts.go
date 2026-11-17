package utils

// Alert fan-out (Batch 2).
//
// SendAlerts is the single trigger point for attack notifications.
// It fans out to every configured channel: the existing Discord
// webhook, Telegram, and email. Each sender is independent: one
// channel failing (or being unconfigured) never blocks the others,
// and every sender fails silently when its own settings are absent,
// so operators who configure nothing new see exactly the previous
// behavior.
//
// Notification types match SendWebhook: 0 is attack start, 1 is
// attack end. Callers run this in a goroutine, as they did with
// SendWebhook.

import (
	"sonushield/core/domains"
	"strconv"
	"strings"
)

func SendAlerts(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {
	SendWebhook(domainData, domainSettings, notificationType)
	SendTelegram(domainData, domainSettings, notificationType)
	SendEmail(domainData, domainSettings, notificationType)
}

// alertText builds the message body for Telegram and email. A custom
// template (attack_start_msg / attack_stop_msg) wins when set;
// otherwise a plain default is built from the live statistics.
// Placeholders follow the Discord webhook convention:
// {{domain.name}}, {{attack.start}}, {{attack.end}}, {{proxy.cpu}},
// {{proxy.ram}}. InitPlaceholders reads the request logger, so it is
// only used when the logger has entries; otherwise only the domain
// name is substituted, which can never panic.
func alertText(template string, domainData domains.DomainData, domain string, notificationType int) string {
	if template != "" {
		if len(domainData.RequestLogger) > 0 {
			return InitPlaceholders(template, domainData, domain)
		}
		return strings.ReplaceAll(template, "{{domain.name}}", domain)
	}
	if notificationType == 0 {
		return "SonuShield alert: attack detected on " + domain +
			" — " + strconv.Itoa(domainData.RequestsPerSecond) + " requests/s total, " +
			strconv.Itoa(domainData.RequestsBypassedPerSecond) + " requests/s allowed."
	}
	return "SonuShield alert: attack on " + domain + " has stopped." +
		" Peak " + strconv.Itoa(domainData.PeakRequestsPerSecond) + " requests/s total, " +
		strconv.Itoa(domainData.PeakRequestsBypassedPerSecond) + " requests/s allowed."
}
