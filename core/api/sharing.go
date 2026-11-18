package api

// Threat sharing API (Batch 8, proxy actions).
//
// GET_SHARING_STATUS (viewer): enabled flag, peer health
// (names, URLs, last success/error), local and received
// indicator counts. Peer secrets are never returned.
// ADD_INDICATOR (operator): params type ("ip" or
// "fingerprint"), value, reason (optional), ttl (seconds,
// optional, default 3600). REMOVE_INDICATOR (operator):
// params type + value. PULL_INDICATORS / PUSH_INDICATORS
// (operator): trigger an immediate pull from / push to all
// peers; no parameters.

import (
	"sonushield/core/sharing"
	"strconv"
)

func sharingStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	enabled, peers, localCount, receivedCount := sharing.Status()
	return map[string]interface{}{
		"ENABLED":  enabled,
		"PEERS":    peers,
		"LOCAL":    localCount,
		"RECEIVED": receivedCount,
	}, ""
}

func addIndicatorResponse(params map[string]string) (map[string]interface{}, string) {
	indType, value, reason, ttl := "", "", "", 3600
	for key, val := range params {
		switch key {
		case "type":
			indType = val
		case "value":
			value = val
		case "reason":
			reason = val
		case "ttl":
			parsed, err := strconv.Atoi(val)
			if err != nil || parsed < 1 {
				return nil, ERR_INVALID_PARAM
			}
			ttl = parsed
		default:
			return nil, ERR_INVALID_PARAM
		}
	}
	if indType != "ip" && indType != "fingerprint" {
		return nil, ERR_INVALID_PARAM
	}
	if value == "" {
		return nil, ERR_INVALID_PARAM
	}
	if !sharing.AddLocal(sharing.Indicator{Type: indType, Value: value, Reason: reason}, ttl) {
		return nil, ERR_INVALID_PARAM
	}
	return map[string]interface{}{"ADDED": true}, ""
}

func removeIndicatorResponse(params map[string]string) (map[string]interface{}, string) {
	indType, value := "", ""
	for key, val := range params {
		switch key {
		case "type":
			indType = val
		case "value":
			value = val
		default:
			return nil, ERR_INVALID_PARAM
		}
	}
	if indType == "" || value == "" {
		return nil, ERR_INVALID_PARAM
	}
	if !sharing.RemoveLocal(indType, value) {
		return nil, ERR_INVALID_PARAM
	}
	return map[string]interface{}{"REMOVED": true}, ""
}

func pullIndicatorsResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	if !sharing.Enabled() {
		return nil, ERR_INVALID_PARAM
	}
	go sharing.PullAll()
	return map[string]interface{}{"PULL_STARTED": true}, ""
}

func pushIndicatorsResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	if !sharing.Enabled() {
		return nil, ERR_INVALID_PARAM
	}
	go sharing.PushAll()
	return map[string]interface{}{"PUSH_STARTED": true}, ""
}
