package api

// Event webhook API (Batch 6), proxy actions, v2 only.
//
//   - GET_WEBHOOK_STATUS (viewer): configured endpoints (host
//     only — never full URLs or secrets), validity, delivery
//     counters, queue depth, and drop count.
//   - TEST_WEBHOOKS (admin): enqueue one test event to every
//     valid endpoint, ignoring type filters, and report how
//     many deliveries were queued. Delivery itself is
//     asynchronous; check GET_WEBHOOK_STATUS for outcomes.
//
// Endpoint configuration is config-file-only: no API action
// reads or writes endpoint URLs or secrets.

import (
	"sonushield/core/events"
)

func webhookStatusResponse() map[string]interface{} {
	st := events.GetStatus()
	endpoints := []map[string]interface{}{}
	for _, ep := range st.Endpoints {
		entry := map[string]interface{}{
			"INDEX":     ep.Index,
			"HOST":      ep.Host,
			"FORMAT":    ep.Format,
			"EVENTS":    ep.Events,
			"VALID":     ep.Valid,
			"DELIVERED": ep.Delivered,
			"FAILED":    ep.Failed,
		}
		if !ep.Valid {
			entry["INVALID_REASON"] = ep.InvalidReason
		}
		endpoints = append(endpoints, entry)
	}
	return map[string]interface{}{
		"ENDPOINTS": endpoints,
		"IGNORED":   st.Ignored,
		"QUEUE":     st.QueueDepth,
		"DROPPED":   st.Dropped,
	}
}

func testWebhooksResponse(params map[string]string) (map[string]interface{}, string) {
	if len(params) != 0 {
		return nil, ERR_INVALID_PARAM
	}
	return map[string]interface{}{
		"QUEUED": events.PublishTest(),
	}, ""
}
