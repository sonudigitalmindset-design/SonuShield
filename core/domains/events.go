package domains

// Signed event webhook configuration (Batch 6). See
// core/events for delivery semantics. Config-file-only: the
// signing secret is never accepted through the API or the
// dashboard, never logged, and redacted from config exports
// along with the URL (webhook URLs often contain tokens).
//
// An endpoint delivers only when it has an http(s) URL and a
// non-empty signing secret: unsigned delivery is never
// attempted. Invalid endpoints are skipped, never fatal.
//
// Format selects the payload encoding: "" or "json" (the
// default JSON envelope), "syslog" (an RFC 5424 line whose
// message is the JSON envelope), or "cef" (a CEF line). All
// formats are delivered by HTTP POST with the same HMAC
// signature headers; see core/events for the exact encodings.
//
// Events filters delivery to the named types ("attack.start",
// "attack.stop", "audit", "test"); empty means all types. The
// TEST_WEBHOOKS action ignores filters: a connectivity test
// must reach every endpoint.
type EventWebhookConfig struct {
	URL            string   `json:"url"`
	Secret         string   `json:"secret"`
	Events         []string `json:"events"`
	Format         string   `json:"format"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	MaxRetries     int      `json:"maxRetries"`
}
