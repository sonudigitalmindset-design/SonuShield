package api

// Domain templates and bulk import (Batch 6).
//
// GET_DOMAIN_TEMPLATES lists the built-in templates with the
// preset each one applies, so the dashboard can show what a
// template sets before it is used.
//
// CREATE_DOMAIN_FROM_TEMPLATE creates one domain from a
// template (params: name, backend, scheme, template,
// certificate, key). IMPORT_DOMAINS creates many at once from a
// JSON array or CSV text (params: format=json|csv, data).
//
// Both writes are all-or-nothing. Every entry is validated
// before anything is written (name, backend, scheme, template,
// certificate/key pairing, and uniqueness against the existing
// config and within the batch); then the full resulting
// configuration is validated with ConfigValidator; only then is
// the file updated (raw-document append, so unknown keys and
// secrets survive untouched) and reloaded. If the reload fails,
// the previous file is restored and the proxy is reloaded
// best-effort, so a failed import leaves nothing changed — the
// same discipline as config rollback. Creating domains reloads
// the configuration, which resets per-domain counters and stage
// state, exactly as a manual reload does; the dashboard says so.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"

	"sonushield/core/domains"
)

const maxImportDomainsSize = 1 << 20 // 1 MB

// domainImportEntry is one imported domain, from JSON or CSV.
// Unknown JSON fields are rejected; unknown CSV columns are
// rejected the same way.
type domainImportEntry struct {
	Name        string `json:"name"`
	Backend     string `json:"backend"`
	Scheme      string `json:"scheme"`
	Template    string `json:"template"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

// domainTemplatesResponse lists the built-in templates with the
// preset domain each one produces (identity fields empty).
func domainTemplatesResponse() map[string]interface{} {
	templates := domains.DomainTemplates()
	list := make([]map[string]interface{}, 0, len(templates))
	for _, tmpl := range templates {
		preset, err := domains.TemplatePreset(domains.Domain{}, tmpl.Name)
		if err != nil {
			continue
		}
		list = append(list, map[string]interface{}{
			"NAME":        tmpl.Name,
			"TITLE":       tmpl.Title,
			"DESCRIPTION": tmpl.Description,
			"PRESET":      preset,
		})
	}
	return map[string]interface{}{
		"TEMPLATES": list,
	}
}

// createDomainFromTemplate validates one template-based domain
// creation and applies it.
func createDomainFromTemplate(params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		switch key {
		case "name", "backend", "scheme", "template", "certificate", "key":
		default:
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	entry := domainImportEntry{
		Name:        params["name"],
		Backend:     params["backend"],
		Scheme:      params["scheme"],
		Template:    params["template"],
		Certificate: params["certificate"],
		Key:         params["key"],
	}
	built, errCode, detail := buildImportedDomains([]domainImportEntry{entry}, []string{"domain"})
	if errCode != "" {
		return nil, errCode, detail
	}
	response, errCode, detail := appendDomainsAndReload(built)
	if errCode != "" {
		return nil, errCode, detail
	}
	response["TEMPLATE"] = templateDisplayName(entry.Template)
	return response, "", ""
}

// importDomains validates a bulk import and applies it, or
// rejects it with nothing changed.
func importDomains(params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		if key != "format" && key != "data" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	raw, ok := params["data"]
	if !ok {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	if len(raw) > maxImportDomainsSize {
		return nil, ERR_INVALID_PARAM, "import payload too large"
	}
	format := strings.ToLower(strings.TrimSpace(params["format"]))
	if format == "" {
		format = "json"
	}
	var entries []domainImportEntry
	var labels []string
	var detail string
	switch format {
	case "json":
		entries, detail = parseImportJSON(raw)
		for i := range entries {
			labels = append(labels, "entry "+strconv.Itoa(i))
		}
	case "csv":
		entries, labels, detail = parseImportCSV(raw)
	default:
		return nil, ERR_INVALID_PARAM, "format must be json or csv"
	}
	if detail != "" {
		return nil, ERR_INVALID_PARAM, detail
	}
	if len(entries) == 0 {
		return nil, ERR_INVALID_PARAM, "no domains to import"
	}
	built, errCode, detail := buildImportedDomains(entries, labels)
	if errCode != "" {
		return nil, errCode, detail
	}
	response, errCode, detail := appendDomainsAndReload(built)
	if errCode != "" {
		return nil, errCode, detail
	}
	response["COUNT"] = len(built)
	return response, "", ""
}

// parseImportJSON decodes a JSON array of import entries.
func parseImportJSON(raw string) ([]domainImportEntry, string) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var entries []domainImportEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, "data is not a JSON array of domain objects: " + err.Error()
	}
	if entries == nil {
		entries = []domainImportEntry{}
	}
	return entries, ""
}

// parseImportCSV decodes CSV text with a header row. Columns:
// name, backend, scheme, template, certificate, key. The header
// must include name and backend; unknown columns are rejected.
// Labels identify rows for error messages (row 1 is the header).
func parseImportCSV(raw string) ([]domainImportEntry, []string, string) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, "data is not valid CSV: " + err.Error()
	}
	if len(records) == 0 {
		return nil, nil, "CSV is empty"
	}
	columns := map[string]int{}
	for i, col := range records[0] {
		name := strings.ToLower(strings.TrimSpace(col))
		switch name {
		case "name", "backend", "scheme", "template", "certificate", "key":
			if _, dup := columns[name]; dup {
				return nil, nil, "CSV header repeats column " + strconv.Quote(name)
			}
			columns[name] = i
		case "":
			return nil, nil, "CSV header has an empty column"
		default:
			return nil, nil, "CSV has unknown column " + strconv.Quote(col)
		}
	}
	if _, ok := columns["name"]; !ok {
		return nil, nil, "CSV header must include a name column"
	}
	if _, ok := columns["backend"]; !ok {
		return nil, nil, "CSV header must include a backend column"
	}
	field := func(record []string, name string) string {
		i, ok := columns[name]
		if !ok || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}
	var entries []domainImportEntry
	var labels []string
	for i, record := range records[1:] {
		empty := true
		for _, value := range record {
			if strings.TrimSpace(value) != "" {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		entries = append(entries, domainImportEntry{
			Name:        field(record, "name"),
			Backend:     field(record, "backend"),
			Scheme:      field(record, "scheme"),
			Template:    field(record, "template"),
			Certificate: field(record, "certificate"),
			Key:         field(record, "key"),
		})
		labels = append(labels, "row "+strconv.Itoa(i+2))
	}
	return entries, labels, ""
}

// buildImportedDomains validates entries and builds the domain
// objects, checking uniqueness within the batch. Labels identify
// entries in error messages. Uniqueness against the existing
// config is checked inside appendDomainsAndReload, under the
// persist lock, where it is authoritative.
func buildImportedDomains(entries []domainImportEntry, labels []string) ([]domains.Domain, string, string) {
	seen := map[string]bool{}
	built := make([]domains.Domain, 0, len(entries))
	for i, entry := range entries {
		label := labels[i]
		name := strings.TrimSpace(entry.Name)
		if !domains.ValidHostname(name) {
			return nil, ERR_INVALID_PARAM, label + ": name must be a valid hostname or IP address"
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return nil, ERR_INVALID_PARAM, label + ": duplicate domain name " + strconv.Quote(name)
		}
		seen[lower] = true
		host, port, ok := domains.SplitBackend(entry.Backend)
		if !ok {
			return nil, ERR_INVALID_PARAM, label + ": backend must be host:port, for example 127.0.0.1:8080"
		}
		scheme := strings.ToLower(strings.TrimSpace(entry.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		if scheme != "http" && scheme != "https" {
			return nil, ERR_INVALID_PARAM, label + ": scheme must be http or https"
		}
		cert := strings.TrimSpace(entry.Certificate)
		key := strings.TrimSpace(entry.Key)
		if (cert == "") != (key == "") {
			return nil, ERR_INVALID_PARAM, label + ": certificate and key must both be set, or both be empty"
		}
		preset, err := domains.TemplatePreset(domains.Domain{
			Name:        name,
			Backend:     net.JoinHostPort(host, port),
			Scheme:      scheme,
			Certificate: cert,
			Key:         key,
		}, entry.Template)
		if err != nil {
			return nil, ERR_INVALID_PARAM, label + ": " + err.Error()
		}
		built = append(built, preset)
	}
	return built, "", ""
}

// templateDisplayName normalizes a template name for responses.
func templateDisplayName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "plain"
	}
	return name
}

// appendDomainsAndReload appends validated domains to config.json
// and reloads. The full resulting configuration is validated
// before anything is written; if the reload fails, the previous
// file is restored and the proxy is reloaded best-effort, so a
// failed call leaves nothing changed.
func appendDomainsAndReload(newDomains []domains.Domain) (map[string]interface{}, string, string) {
	if ConfigValidator == nil || ConfigReloader == nil {
		return nil, ERR_ACTION_NOT_FOUND, ""
	}
	persistMutex.Lock()
	defer persistMutex.Unlock()

	previous, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(previous, &cfg); err != nil {
		return nil, ERR_INVALID_PARAM, "config.json is not valid JSON: " + err.Error()
	}
	seen := map[string]bool{}
	for _, d := range cfg.Domains {
		seen[strings.ToLower(d.Name)] = true
	}
	for _, d := range newDomains {
		if seen[strings.ToLower(d.Name)] {
			return nil, ERR_INVALID_PARAM, "domain " + strconv.Quote(d.Name) + " already exists"
		}
		seen[strings.ToLower(d.Name)] = true
	}
	candidate := cfg
	candidate.Domains = append(append([]domains.Domain{}, cfg.Domains...), newDomains...)
	if err := ConfigValidator(&candidate); err != nil {
		return nil, ERR_INVALID_PARAM, "resulting config failed validation: " + err.Error()
	}

	doc, err := loadConfigDocument()
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	var domainList []json.RawMessage
	if rawDomains, ok := doc["domains"]; ok {
		if err := json.Unmarshal(rawDomains, &domainList); err != nil {
			return nil, ERR_INVALID_PARAM, "config.json domains list is not valid: " + err.Error()
		}
	}
	for _, d := range newDomains {
		encoded, err := json.Marshal(d)
		if err != nil {
			return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
		}
		domainList = append(domainList, encoded)
	}
	rebuilt, err := json.Marshal(domainList)
	if err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	doc["domains"] = rebuilt
	if err := saveConfigDocument(doc); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}
	if err := ConfigReloader(); err != nil {
		// Roll the file swap back, then reload best-effort so
		// the running proxy matches the file again.
		_ = writeConfigBytesAtomic(previous)
		_ = ConfigReloader()
		return nil, ERR_RELOAD_FAILED, err.Error()
	}
	names := make([]string, 0, len(newDomains))
	for _, d := range newDomains {
		names = append(names, d.Name)
	}
	return map[string]interface{}{
		"CREATED":  names,
		"RELOADED": true,
	}, "", ""
}
