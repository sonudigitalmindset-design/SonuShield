package domains

// Stripe usage-based billing configuration (Batch 6). See
// core/billing for the reporting semantics. Config-file-only:
// the secret key is never accepted through the API or the
// dashboard, never logged, and never returned by any API action.
//
// Disabled by default: an empty SecretKey means no reporting of
// any kind, scheduled or manual. Customers maps normalized
// tenant names (see NormalizeTenant; "default" for unassigned
// domains) to their Stripe customer and metered subscription
// items. A tenant without a mapping is never reported.
//
// ReportIntervalSeconds drives the background reporter; 0 (the
// default) disables scheduled reporting while leaving the
// manual REPORT_STRIPE_USAGE action available. The reporter
// clamps the interval to 60-86400 seconds.
//
// APIBase defaults to https://api.stripe.com and exists only so
// tests and the smoke harness can point the client at a mock
// server. Never point it at an untrusted server with a real key:
// requests carry the secret key as HTTP Basic auth.
type StripeConfig struct {
	SecretKey             string                           `json:"secretKey"`
	APIBase               string                           `json:"apiBase"`
	ReportIntervalSeconds int                              `json:"reportIntervalSeconds"`
	Customers             map[string]StripeCustomerMapping `json:"customers"`
}

// StripeCustomerMapping links one tenant to its Stripe customer
// and metered subscription items. Either item may be empty: that
// metric is then not reported for the tenant. Quantities are
// reported in raw units — requests as a count, bandwidth as
// bytes — so the operator's metered prices must be defined in
// those units (for example a price per byte, or per million
// requests via the unit amount).
type StripeCustomerMapping struct {
	CustomerID      string `json:"customerId"`
	RequestsItemID  string `json:"requestsItemId"`
	BandwidthItemID string `json:"bandwidthItemId"`
}
