package api

// On-call status API (Batch 8, proxy actions).
//
// GET_ONCALL_STATUS (viewer): whether the rotation is
// enabled, the currently on-call responder's name (empty
// during a gap), the escalation delay, responder names, and
// the open alerts with age and escalation state. Responder
// channel settings and secrets are never returned.
// ACK_ALERT (operator): param "id" acknowledges one open
// alert, stopping its escalation.

import (
	"sonushield/core/oncalls"
	"time"
)

func onCallStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	enabled := oncalls.Enabled()
	current := ""
	if enabled {
		if responder, ok := oncalls.Resolve(time.Now()); ok {
			current = responder.Name
		}
	}
	names := []string{}
	for _, responder := range oncalls.Responders() {
		names = append(names, responder.Name)
	}
	open := []map[string]interface{}{}
	for _, alert := range oncalls.Open() {
		open = append(open, map[string]interface{}{
			"ID":         alert.ID,
			"TITLE":      alert.Title,
			"DOMAIN":     alert.Domain,
			"CREATED_AT": alert.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			"AGE_SECONDS": int64(time.Since(alert.CreatedAt) / time.Second),
			"ESCALATED":  alert.Escalated,
		})
	}
	return map[string]interface{}{
		"ENABLED":            enabled,
		"CURRENT":            current,
		"ESCALATION_MINUTES": oncalls.EscalationMinutes(),
		"RESPONDERS":         names,
		"OPEN_ALERTS":        open,
	}, ""
}

func ackAlertResponse(params map[string]string) (map[string]interface{}, string) {
	id := ""
	for key, value := range params {
		if key != "id" {
			return nil, ERR_INVALID_PARAM
		}
		id = value
	}
	if id == "" || !oncalls.Ack(id) {
		return nil, ERR_INVALID_PARAM
	}
	return map[string]interface{}{"ACKNOWLEDGED": true}, ""
}
