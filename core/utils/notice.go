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
	"sonushield/core/oncalls"
	"sonushield/core/pnc"
)

// SendNotice fans a title + body out to every configured alert
// channel for the domain. It never logs, and it never fails:
// unconfigured or broken channels are skipped silently.
// Under an active on-call rotation the notice goes to the
// on-call responder's channels and is tracked for
// acknowledgement (see utils/oncall.go).
func SendNotice(domainSettings domains.DomainSettings, title, body string) {
	defer pnc.PanicHndl()

	resolved, tracked := resolveOnCallSettings(domainSettings)
	text := title + "\n" + body
	sendTelegramText(resolved.DomainTelegram, text)
	sendEmailText(resolved.DomainEmail, "SonuShield: "+title, body)
	sendTwilioText(resolved.DomainTwilio, text)
	sendDiscordText(resolved.DomainWebhooks, title, body)
	if tracked {
		oncalls.Track(title, body, domainSettings.Name)
	}
}
