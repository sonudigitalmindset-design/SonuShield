package api

// Maintenance override API (Batch 7).
//
// SET_MAINTENANCE enables or disables the on-demand
// maintenance override for a domain. Parameters:
//   - ENABLED: "true" or "false" (required).
//   - MESSAGE: optional page text, at most 500 characters.
//     Empty clears the stored message (the page falls back
//     to its default text).
//   - DURATION_MINUTES: optional non-negative integer; the
//     override expires that many minutes after being set.
//     0 or absent means "until disabled".
// The override is in-memory only: it survives config
// reloads but not a process restart.
//
// GET_MAINTENANCE reports the override state, the scheduled
// windows from the configuration, and whether maintenance
// is effectively active right now.

import (
	"strconv"
	"strings"
	"time"

	"sonushield/core/domains"
	"sonushield/core/maintenance"
)

const maxMaintenanceMessage = 500

// setMaintenanceResponse builds the SET_MAINTENANCE
// response.
func setMaintenanceResponse(domain string, params map[string]string) (map[string]interface{}, string, string) {
	enabledText, ok := params["ENABLED"]
	if !ok {
		return nil, ERR_PARAMS_REQUIRED, "ENABLED is required"
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(enabledText))
	if err != nil {
		return nil, ERR_INVALID_PARAM, "ENABLED must be true or false"
	}
	message := params["MESSAGE"]
	if len(message) > maxMaintenanceMessage {
		return nil, ERR_INVALID_PARAM, "MESSAGE is too long (max 500 characters)"
	}
	duration := 0
	if text, ok := params["DURATION_MINUTES"]; ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || parsed < 0 {
			return nil, ERR_INVALID_PARAM, "DURATION_MINUTES must be a non-negative integer"
		}
		duration = parsed
	}
	for key := range params {
		if key != "ENABLED" && key != "MESSAGE" && key != "DURATION_MINUTES" {
			return nil, ERR_INVALID_PARAM, "unknown parameter: " + key
		}
	}
	until := time.Time{}
	if enabled && duration > 0 {
		until = time.Now().Add(time.Duration(duration) * time.Minute)
	}
	maintenance.Set(domain, enabled, message, until)
	response := map[string]interface{}{
		"ENABLED": enabled,
		"MESSAGE": message,
	}
	if !until.IsZero() {
		response["UNTIL"] = until.Format(time.RFC3339)
	}
	return response, "", ""
}

// getMaintenanceResponse builds the GET_MAINTENANCE
// response.
func getMaintenanceResponse(domain string, params map[string]string) (map[string]interface{}, string, string) {
	for range params {
		return nil, ERR_INVALID_PARAM, ""
	}
	now := time.Now()
	override, hasOverride := maintenance.Get(domain)
	overrideActive, _ := maintenance.Active(domain, now)

	windows := []map[string]interface{}{}
	scheduledActive := false
	scheduledMessage := ""
	if domains.Config != nil {
		for _, configured := range domains.Config.Domains {
			if configured.Name != domain {
				continue
			}
			for _, window := range configured.MaintenanceWindows {
				windows = append(windows, map[string]interface{}{
					"START":   window.Start,
					"END":     window.End,
					"MESSAGE": window.Message,
				})
			}
			parsed, _ := domains.ParseMaintenanceWindows(configured.MaintenanceWindows)
			scheduledActive, scheduledMessage = domains.MaintenanceActiveAt(parsed, now)
			break
		}
	}

	effective, message := scheduledActive, scheduledMessage
	if overrideActive {
		effective = true
		message = override.Message
	}
	response := map[string]interface{}{
		"DOMAIN":            domain,
		"OVERRIDE_ENABLED":  hasOverride && override.Enabled,
		"OVERRIDE_MESSAGE":  override.Message,
		"OVERRIDE_ACTIVE":   overrideActive,
		"SCHEDULED_WINDOWS": windows,
		"SCHEDULED_ACTIVE":  scheduledActive,
		"EFFECTIVE_ACTIVE":  effective,
		"EFFECTIVE_MESSAGE": message,
	}
	if hasOverride && !override.Until.IsZero() {
		response["OVERRIDE_UNTIL"] = override.Until.Format(time.RFC3339)
	}
	return response, "", ""
}
