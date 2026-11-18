package api

// Community rule packs (Batch 7).
//
// IMPORT_RULE_PACK imports a rule pack — a JSON document
// with metadata plus a rules array — from an
// operator-supplied file path or URL, into one domain.
// Packs are OPERATOR-CHOSEN: SonuShield ships no bundled
// packs, endorses no pack author, and never fetches a pack
// unless the operator asks for one by source.
//
// Pack document:
//
//	{
//	  "name": "example-pack", "version": "1.0.0",
//	  "source": "https://example.com/pack.json",
//	  "description": "What the pack does.",
//	  "rules": [{"expression": "...", "action": "4"}]
//	}
//
// Every rule goes through the same validation as rule CRUD
// (expression compiles, known fields only, valid action,
// valid schedule), and the whole resulting list is compiled
// before anything is stored, so an invalid pack is rejected
// with nothing changed (all-or-nothing). URL fetches use a
// 10-second timeout, at most 3 redirects, http/https only,
// and a 1 MB size cap; a failed fetch fails the import
// cleanly and never affects traffic. File reads run with
// the proxy process's filesystem privileges, like every
// other operator action.
//
// Pack metadata is recorded in a registry kept in
// config.json under proxy.rulePacks (metadata only — the
// rules themselves live in the domain's firewallRules).
// LIST_RULE_PACKS returns the registry. The registry has no
// struct field: it is read from and written to the raw
// config document, so it survives reloads and unknown-key
// preservation like any other config data.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sonushield/core/domains"
)

const (
	maxPackSize       = 1 << 20 // 1 MB
	maxPackRules      = 1000
	maxPackNameLen    = 100
	maxPackVersionLen = 50
	maxPackDescLen    = 1000
	packFetchTimeout  = 10 * time.Second
	packMaxRedirects  = 3
)

// rulePack is the on-disk / on-the-wire pack document.
type rulePack struct {
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Source      string             `json:"source"`
	Description string             `json:"description"`
	Rules       []domains.JsonRule `json:"rules"`
}

// rulePackRecord is one registry entry under
// proxy.rulePacks in config.json.
type rulePackRecord struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Source      string `json:"source"`
	Description string `json:"description"`
	Domain      string `json:"domain"`
	RuleCount   int    `json:"ruleCount"`
	Mode        string `json:"mode"`
	ImportedAt  string `json:"importedAt"`
}

// importRulePack validates and applies a rule pack from
// params SOURCE (file path or URL) and MODE (replace|append).
func importRulePack(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		if key != "SOURCE" && key != "MODE" {
			return nil, ERR_INVALID_PARAM, "unknown parameter: " + key
		}
	}
	source, ok := params["SOURCE"]
	if !ok || strings.TrimSpace(source) == "" {
		return nil, ERR_PARAMS_REQUIRED, "SOURCE is required"
	}
	mode := strings.ToLower(strings.TrimSpace(params["MODE"]))
	if mode == "" {
		mode = "replace"
	}
	if mode != "replace" && mode != "append" {
		return nil, ERR_INVALID_PARAM, "MODE must be replace or append"
	}

	data, err := fetchPackSource(strings.TrimSpace(source))
	if err != nil {
		return nil, ERR_FETCH_FAILED, err.Error()
	}
	pack, err := parseRulePack(data)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	for i, rule := range pack.Rules {
		if err := validateRule(rule); err != nil {
			return nil, ERR_INVALID_PARAM, "rule " + strconv.Itoa(i) + ": " + err.Error()
		}
	}

	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	settings, ok := loadFreshSettings(domainName)
	if !ok {
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	var newRaw []domains.JsonRule
	switch mode {
	case "append":
		newRaw = make([]domains.JsonRule, 0, len(settings.RawCustomRules)+len(pack.Rules))
		newRaw = append(newRaw, settings.RawCustomRules...)
		newRaw = append(newRaw, pack.Rules...)
	default:
		newRaw = pack.Rules
	}
	response, errCode, detail := applyRuleList(domainName, settings, newRaw)
	if errCode != "" {
		return nil, errCode, detail
	}

	// Record the import. The rules are already live; a
	// registry failure is reported as a warning, not an
	// error, because the registry is advisory metadata.
	recordSource := pack.Source
	if recordSource == "" {
		recordSource = strings.TrimSpace(source)
	}
	record := rulePackRecord{
		Name:        pack.Name,
		Version:     pack.Version,
		Source:      recordSource,
		Description: pack.Description,
		Domain:      domainName,
		RuleCount:   len(pack.Rules),
		Mode:        mode,
		ImportedAt:  time.Now().Format(time.RFC3339),
	}
	if err := appendPackRecord(record); err != nil {
		response["REGISTRY_WARNING"] = "rules applied, but the pack registry could not be updated: " + err.Error()
	}
	response["PACK_NAME"] = pack.Name
	response["PACK_VERSION"] = pack.Version
	response["IMPORTED"] = len(pack.Rules)
	return response, "", ""
}

// parseRulePack decodes and validates a pack document.
func parseRulePack(data []byte) (*rulePack, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var pack rulePack
	if err := decoder.Decode(&pack); err != nil {
		return nil, errors.New("pack is not a valid rule-pack document: " + err.Error())
	}
	if strings.TrimSpace(pack.Name) == "" {
		return nil, errors.New("pack name is required")
	}
	if len(pack.Name) > maxPackNameLen {
		return nil, errors.New("pack name is too long (max 100 characters)")
	}
	if strings.TrimSpace(pack.Version) == "" {
		return nil, errors.New("pack version is required")
	}
	if len(pack.Version) > maxPackVersionLen {
		return nil, errors.New("pack version is too long (max 50 characters)")
	}
	if len(pack.Description) > maxPackDescLen {
		return nil, errors.New("pack description is too long (max 1000 characters)")
	}
	if len(pack.Rules) == 0 {
		return nil, errors.New("pack contains no rules")
	}
	if len(pack.Rules) > maxPackRules {
		return nil, errors.New("pack contains too many rules (max 1000)")
	}
	return &pack, nil
}

// fetchPackSource reads a pack from a URL or a file path.
// URLs are limited to http/https, 10 seconds, 3 redirects,
// and 1 MB. Anything else is treated as a local file path.
func fetchPackSource(source string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return fetchPackURL(source)
	}
	if strings.Contains(source, "://") {
		return nil, errors.New("unsupported source scheme: only http://, https://, and file paths are accepted")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, errors.New("could not read pack file: " + err.Error())
	}
	if len(data) > maxPackSize {
		return nil, errors.New("pack file exceeds the 1 MB size cap")
	}
	return data, nil
}

// fetchPackURL GETs a pack over HTTP with timeout,
// redirect, and size limits.
func fetchPackURL(source string) ([]byte, error) {
	client := &http.Client{
		Timeout: packFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= packMaxRedirects {
				return errors.New("too many redirects (max 3)")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return errors.New("redirect to a non-http(s) URL is not allowed")
			}
			return nil
		},
	}
	resp, err := client.Get(source)
	if err != nil {
		return nil, errors.New("could not fetch pack: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("pack URL returned HTTP " + strconv.Itoa(resp.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPackSize+1))
	if err != nil {
		return nil, errors.New("could not read pack response: " + err.Error())
	}
	if len(data) > maxPackSize {
		return nil, errors.New("pack response exceeds the 1 MB size cap")
	}
	return data, nil
}

// appendPackRecord adds one entry to the proxy.rulePacks
// registry in config.json.
func appendPackRecord(record rulePackRecord) error {
	return updateConfigProxy(func(proxyObj map[string]json.RawMessage) error {
		var records []rulePackRecord
		if raw, ok := proxyObj["rulePacks"]; ok {
			if err := json.Unmarshal(raw, &records); err != nil {
				return errors.New("proxy.rulePacks registry is not valid: " + err.Error())
			}
		}
		records = append(records, record)
		return setRawField(proxyObj, "rulePacks", records)
	})
}

// listRulePacksResponse builds the LIST_RULE_PACKS
// response from the registry in config.json.
func listRulePacksResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	records := []rulePackRecord{}
	doc, err := loadConfigDocument()
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}
	if raw, ok := doc["proxy"]; ok {
		var proxyObj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &proxyObj); err == nil {
			if rawPacks, ok := proxyObj["rulePacks"]; ok {
				// A corrupt registry reports empty rather
				// than failing the whole action; the
				// registry is advisory metadata.
				_ = json.Unmarshal(rawPacks, &records)
			}
		}
	}
	if records == nil {
		records = []rulePackRecord{}
	}
	return map[string]interface{}{
		"PACKS": records,
		"COUNT": len(records),
	}, ""
}
