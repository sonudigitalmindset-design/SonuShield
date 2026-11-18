package domains

// On-call rotation configuration (Batch 8).
//
// OnCallConfig routes alert delivery to the responder who is
// on call, instead of the domain's configured channels. When
// enabled and a schedule entry matches the current time, each
// alert channel uses the on-call responder's settings; a
// channel the responder did not configure is skipped. When no
// schedule entry matches, alerts fall back to the domain's
// configured channels, so alerts still go somewhere during a
// gap. When disabled (the default), delivery is exactly as
// before: every configured channel for the domain.
//
// EscalationMinutes, when positive, re-sends an
// unacknowledged alert to every responder in the rotation
// after that many minutes. Alerts are acknowledged through
// the ACK_ALERT API action. Handover is the schedule itself:
// at a boundary, new alerts go to the next responder; open
// alerts keep escalating to the whole rotation.
//
// Responder channel settings reuse the domain channel
// structs, so the same transports deliver them. Tokens,
// passwords, and webhook URLs in responder settings are
// secrets: they are config-only and redacted from exports
// and backups like the domain equivalents.

// OnCallResponder is one person in the rotation, with
// per-channel overrides. A channel left empty is skipped
// while this responder is on call.
type OnCallResponder struct {
	Name     string           `json:"name"`
	Telegram TelegramSettings `json:"telegram"`
	Email    EmailSettings    `json:"email"`
	Twilio   TwilioSettings   `json:"twilio"`
	Webhook  WebhookSettings  `json:"webhook"`
}

// OnCallEntry is one schedule entry: the named responder is
// on call on the listed days between Start and End (HH:MM,
// 24-hour) in Timezone (IANA name, UTC when empty or
// invalid). Days use three-letter lowercase names
// ("mon".."sun"). An end earlier than the start spans
// midnight; equal start and end means the whole day. The
// first matching entry in config order wins.
type OnCallEntry struct {
	Responder string   `json:"responder"`
	Days      []string `json:"days"`
	Start     string   `json:"start"`
	End       string   `json:"end"`
	Timezone  string   `json:"timezone"`
}

// OnCallConfig is the proxy-level on-call configuration
// (proxy.oncall).
type OnCallConfig struct {
	Enabled           bool              `json:"enabled"`
	Responders        []OnCallResponder `json:"responders"`
	Schedule          []OnCallEntry     `json:"schedule"`
	EscalationMinutes int               `json:"escalationMinutes"`
}
