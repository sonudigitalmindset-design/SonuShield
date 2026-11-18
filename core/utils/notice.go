package utils

// Generic operator notices (Batch 7).
//
// SendNotice delivers one short operator-facing message over
// every alert channel the domain configured (Discord webhook,
// Telegram, email, Twilio), reusing the attack-alert transports
// with caller-supplied text. It is used for events that are
// not attacks: canary-token hits, marker hits, certificate
// expiry, and subdomain changes.
//
// Like SendAlerts, each channel is independent and fails
// silently when unconfigured, and callers run it in a
// goroutine so delivery never blocks request handling.
// Callers must never put secrets in the title or body: canary
// token VALUES are never included, only the fact that one was
// used and where.

import (
	"sonushield/core/domains"
	"sonushield/core/pnc"
)

// SendNotice fans a title + body out to every configured alert
// channel for the domain. It never logs, and it never fails:
// unconfigured or broken channels are skipped silently.
func SendNotice(domainSettings domains.DomainSettings, title, body string) {
	defer pnc.PanicHndl()

	text := title + "\n" + body
	sendTelegramText(domainSettings.DomainTelegram, text)
	sendEmailText(domainSettings.DomainEmail, "SonuShield: "+title, body)
	sendTwilioText(domainSettings.DomainTwilio, text)
	sendDiscordText(domainSettings.DomainWebhooks, title, body)
}
