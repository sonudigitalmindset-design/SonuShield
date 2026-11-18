package api

// Stripe billing API (Batch 6), proxy actions, v2 only.
//
//   - GET_STRIPE_STATUS (viewer): billing configuration summary
//     (enabled, key mode, interval, mapped tenants) plus the
//     last report outcome. Never includes the secret key.
//   - REPORT_STRIPE_USAGE (admin): run one usage report now
//     (same semantics as the scheduled reporter) and return
//     the per-tenant results. Takes no parameters.
//
// Billing configuration itself (keys, mappings) is
// config-file-only: no API action reads or writes it.

import (
	"sonushield/core/billing"
)

func stripeStatusResponse() map[string]interface{} {
	st := billing.GetStatus()
	mapped := []map[string]interface{}{}
	for _, m := range st.Mapped {
		entry := map[string]interface{}{
			"TENANT":            m.Tenant,
			"CUSTOMER_ID":       m.CustomerID,
			"REQUESTS_ITEM_ID":  m.RequestsItemID,
			"BANDWIDTH_ITEM_ID": m.BandwidthItemID,
			"VALID":             m.Valid,
		}
		if !m.Valid {
			entry["INVALID_REASON"] = m.InvalidReason
		}
		mapped = append(mapped, entry)
	}
	response := map[string]interface{}{
		"ENABLED":  st.Enabled,
		"KEY_MODE": st.KeyMode,
		"INTERVAL": st.Interval,
		"MAPPED":   mapped,
	}
	if st.Last != nil {
		response["LAST_REPORT"] = reportOutcomeResponse(*st.Last)
	}
	return response
}

func reportOutcomeResponse(outcome billing.ReportOutcome) map[string]interface{} {
	results := []map[string]interface{}{}
	for _, r := range outcome.Results {
		entry := map[string]interface{}{
			"TENANT":   r.Tenant,
			"METRIC":   string(r.Metric),
			"STATUS":   r.Status,
			"QUANTITY": r.Quantity,
		}
		if r.Detail != "" {
			entry["DETAIL"] = r.Detail
		}
		results = append(results, entry)
	}
	return map[string]interface{}{
		"TIME":     outcome.Time.Unix(),
		"DISABLED": outcome.Disabled,
		"REASON":   outcome.Reason,
		"RESULTS":  results,
	}
}

func reportStripeUsageResponse(params map[string]string) (map[string]interface{}, string) {
	if len(params) != 0 {
		return nil, ERR_INVALID_PARAM
	}
	return reportOutcomeResponse(billing.ReportOnce()), ""
}
