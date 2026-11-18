package utils

// On-call delivery integration (Batch 8).
//
// When the on-call rotation is enabled and a responder is on
// call, SendNotice and SendAlerts deliver to the responder's
// channels instead of the domain's configured channels: each
// channel uses the responder's settings, and a channel the
// responder did not configure is skipped. When no responder
// is on call, delivery falls back to the domain's channels.
// When the rotation is disabled, this file changes nothing.
//
// Open alerts are tracked in the oncalls package. Notices
// delivered under a rotation are tracked for
// acknowledgement; attack-start alerts are tracked under a
// fixed ID and cleared by the matching attack-end. The
// escalation ticker re-sends unacknowledged alerts to every
// responder once the escalation delay elapses. Escalation
// re-sends the stored generic text, not any per-channel
// template rendering.

import (
	"sonushield/core/domains"
	"sonushield/core/oncalls"
	"sync"
	"time"
)

// resolveOnCallSettings applies the on-call rotation to a
// domain's alert settings. It reports whether a responder
// was resolved (and therefore whether the alert should be
// tracked for acknowledgement).
func resolveOnCallSettings(settings domains.DomainSettings) (domains.DomainSettings, bool) {
	if !oncalls.Enabled() {
		return settings, false
	}
	responder, ok := oncalls.Resolve(time.Now())
	if !ok {
		return settings, false
	}
	resolved := settings
	resolved.DomainTelegram = responder.Telegram
	resolved.DomainEmail = responder.Email
	resolved.DomainTwilio = responder.Twilio
	resolved.DomainWebhooks = responder.Webhook
	return resolved, true
}

// sendNoticeToAllResponders delivers a notice to every
// responder's configured channels. Used for escalations.
func sendNoticeToAllResponders(title, body string) {
	text := title + "\n" + body
	for _, responder := range oncalls.Responders() {
		sendTelegramText(responder.Telegram, text)
		sendEmailText(responder.Email, "SonuShield: "+title, body)
		sendTwilioText(responder.Twilio, text)
		sendDiscordText(responder.Webhook, title, body)
	}
}

var escalationOnce sync.Once

// StartOnCallEscalation starts the escalation ticker exactly
// once. It is called from Serve; inert unless the rotation
// is enabled with a positive escalation delay.
func StartOnCallEscalation() {
	escalationOnce.Do(func() { go escalationLoop() })
}

func escalationLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		for _, alert := range oncalls.DueEscalations(time.Now()) {
			sendNoticeToAllResponders("ESCALATED: "+alert.Title, alert.Body)
		}
	}
}
