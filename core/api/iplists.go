package api

// IP allow/block list management (Batch 5).
//
//   - GET_IP_LISTS (domain, viewer): the live (unexpired) entries
//     of both lists.
//   - ADD_IP_ENTRY (domain, operator): add or update one entry.
//     Params: list (allowlist|blocklist), target (IP or CIDR),
//     expires (unix seconds, optional, 0 = never), note
//     (optional, max 200 characters). An entry with the same
//     target string already in the list is updated in place.
//   - REMOVE_IP_ENTRY (domain, operator): remove one entry.
//     Params: list, target (exact string match).
//
// Writes persist to config.json first (atomic, with backup,
// through updateConfigDomain) and only then apply to the running
// proxy, like rule CRUD. Expired entries are pruned on every
// write. Unknown parameters are rejected.

import (
	"encoding/json"
	"sonushield/core/domains"
	"strconv"
	"strings"
	"time"
)

const maxIPEntryNoteLen = 200

func ipEntryResponse(entry domains.IPListEntry) map[string]interface{} {
	return map[string]interface{}{
		"TARGET":  entry.Target,
		"EXPIRES": entry.Expires,
		"NOTE":    entry.Note,
	}
}

func ipListsResponse(domainSettings *domains.DomainSettings) map[string]interface{} {
	allow := []map[string]interface{}{}
	for _, entry := range domains.PruneExpiredIPEntries(domainSettings.IPAllowlist) {
		allow = append(allow, ipEntryResponse(entry))
	}
	block := []map[string]interface{}{}
	for _, entry := range domains.PruneExpiredIPEntries(domainSettings.IPBlocklist) {
		block = append(block, ipEntryResponse(entry))
	}
	return map[string]interface{}{
		"ALLOWLIST": allow,
		"BLOCKLIST": block,
	}
}

// ipListParams validates the shared list/target params. It
// returns the config-file key ("ipAllowlist"/"ipBlocklist"), the
// target, and an error code ("" when valid).
func ipListParams(params map[string]string) (string, string, string) {
	listName, ok := params["list"]
	if !ok {
		return "", "", ERR_PARAMS_REQUIRED
	}
	var key string
	switch strings.ToLower(strings.TrimSpace(listName)) {
	case "allowlist":
		key = "ipAllowlist"
	case "blocklist":
		key = "ipBlocklist"
	default:
		return "", "", ERR_INVALID_PARAM
	}
	target, ok := params["target"]
	if !ok || target == "" || !domains.ValidateIPTarget(target) {
		return "", "", ERR_INVALID_PARAM
	}
	return key, target, ""
}

// applyIPEntry validates, persists, and applies one add/update.
func applyIPEntry(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	key, target, errCode := ipListParams(params)
	if errCode != "" {
		return nil, errCode
	}
	var expires int64
	note := ""
	for param, value := range params {
		switch param {
		case "list", "target":
		case "expires":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || parsed < 0 || (parsed != 0 && parsed <= time.Now().Unix()) {
				return nil, ERR_INVALID_PARAM
			}
			expires = parsed
		case "note":
			note = value
			if len(note) > maxIPEntryNoteLen {
				note = note[:maxIPEntryNoteLen]
			}
		default:
			return nil, ERR_INVALID_PARAM
		}
	}

	updated := *domainSettings
	var list []domains.IPListEntry
	if key == "ipAllowlist" {
		list = domains.PruneExpiredIPEntries(updated.IPAllowlist)
	} else {
		list = domains.PruneExpiredIPEntries(updated.IPBlocklist)
	}
	found := false
	for i := range list {
		if list[i].Target == target {
			list[i].Expires = expires
			list[i].Note = note
			found = true
			break
		}
	}
	if !found {
		list = append(list, domains.IPListEntry{Target: target, Expires: expires, Note: note})
	}
	if key == "ipAllowlist" {
		updated.IPAllowlist = list
	} else {
		updated.IPBlocklist = list
	}

	if err := updateConfigDomain(updated.Name, func(domain map[string]json.RawMessage) error {
		return setRawField(domain, key, list)
	}); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}

	updated.RebuildIPLists()
	domains.DomainsMap.Store(updated.Name, updated)
	syncDomainConfigMemory(updated.Name, func(domain *domains.Domain) {
		if key == "ipAllowlist" {
			domain.IPAllowlist = list
		} else {
			domain.IPBlocklist = list
		}
	})
	return ipListsResponse(&updated), ""
}

// removeIPEntry validates, persists, and applies one removal.
func removeIPEntry(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	key, target, errCode := ipListParams(params)
	if errCode != "" {
		return nil, errCode
	}
	for param := range params {
		switch param {
		case "list", "target":
		default:
			return nil, ERR_INVALID_PARAM
		}
	}

	updated := *domainSettings
	var list []domains.IPListEntry
	if key == "ipAllowlist" {
		list = domains.PruneExpiredIPEntries(updated.IPAllowlist)
	} else {
		list = domains.PruneExpiredIPEntries(updated.IPBlocklist)
	}
	kept := make([]domains.IPListEntry, 0, len(list))
	removed := false
	for _, entry := range list {
		if entry.Target == target {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !removed {
		return nil, ERR_INVALID_PARAM
	}
	if key == "ipAllowlist" {
		updated.IPAllowlist = kept
	} else {
		updated.IPBlocklist = kept
	}

	if err := updateConfigDomain(updated.Name, func(domain map[string]json.RawMessage) error {
		return setRawField(domain, key, kept)
	}); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}

	updated.RebuildIPLists()
	domains.DomainsMap.Store(updated.Name, updated)
	syncDomainConfigMemory(updated.Name, func(domain *domains.Domain) {
		if key == "ipAllowlist" {
			domain.IPAllowlist = kept
		} else {
			domain.IPBlocklist = kept
		}
	})
	return ipListsResponse(&updated), ""
}
