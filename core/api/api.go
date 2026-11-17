package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/proxy"
	"sonushield/core/utils"
	"strings"
)

// ConfigReloader, when set, performs a validated configuration
// reload and reports success or failure without panicking. It is a
// hook rather than a direct call because the server package (which
// owns the reload) imports this package. The server package sets it
// at init time; if it is unset, RELOAD reports the action as
// unavailable instead of touching anything.
var ConfigReloader func() error

func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	role, ok := proxy.RoleForSecret(request.Header.Get("proxy-secret"))
	if !ok {
		auditUnauthenticated(request, "", "")
		return false
	}

	// The recorder captures the response so the deferred audit
	// entry can report the real outcome on every return path.
	recorder := &auditRecorder{ResponseWriter: writer}
	var action, domain string
	var params map[string]string
	defer func() {
		auditAction(request, role, action, domain, params, recorder.captured)
	}()

	reqBody, err := io.ReadAll(request.Body)
	if err != nil {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_BODY_READ_FAILED,
		})
	}

	defer request.Body.Close()

	var apiRequest API_REQUEST
	err = json.Unmarshal(reqBody, &apiRequest)
	if err != nil {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_JSON_READ_FAILED,
		})
		return true
	}

	action, domain, params = apiRequest.Action, apiRequest.Domain, apiRequest.Params

	// Roles: unknown actions fall through to the handlers, which
	// answer ERR_ACTION_NOT_FOUND exactly as before.
	if known, allowed := authorize(role, action); known && !allowed {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_FORBIDDEN,
		})
		return true
	}

	if apiRequest.Domain == "" {
		handleProxyActions(apiRequest.Action, recorder, apiRequest.Params)
		return true
	}

	uncastedDomainSettings, ok := domains.DomainsMap.Load(apiRequest.Domain)
	if !ok {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}
	domainSettings, _ := uncastedDomainSettings.(domains.DomainSettings)

	handleDomainActions(apiRequest.Action, recorder, &domainData, &domainSettings, apiRequest.Params)
	return true
}

func handleProxyActions(action string, writer http.ResponseWriter, params map[string]string) {
	switch action {
	case "GET_PROXY_STATS":
		APIResponse(writer, true, map[string]interface{}{
			"CPU_USAGE": proxy.CpuUsage,
			"RAM_USAGE": proxy.RamUsage,
		})
	case "GET_PROXY_STATS_CPU_USAGE":
		APIResponse(writer, true, map[string]interface{}{
			"CPU_USAGE": proxy.CpuUsage,
		})
	case "GET_PROXY_STATS_RAM_USAGE":
		APIResponse(writer, true, map[string]interface{}{
			"RAM_USAGE": proxy.RamUsage,
		})
	case "GET_IP_REQUESTS":
		firewall.Mutex.RLock()
		ipsAll := firewall.AccessIps
		ipsCookie := firewall.AccessIpsCookie
		firewall.Mutex.RUnlock()

		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_IP_REQUESTS":     ipsAll,
			"CHALLENGE_IP_REQUESTS": ipsCookie,
		})
	//Only returns UNK Fingerprints
	case "GET_FINGERPRINT_REQUESTS":
		firewall.Mutex.RLock()
		ipsFps := firewall.UnkFps
		firewall.Mutex.RUnlock()

		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_FINGERPRINT_REQUESTS": ipsFps,
		})
	case "GET_IP_CACHE":
		cacheIps := make(map[string]interface{})
		firewall.CacheIps.Range(func(key, value any) bool {
			cacheIps[fmt.Sprint(key)] = value
			return true
		})

		APIResponse(writer, true, map[string]interface{}{
			"IP_CACHE": cacheIps,
		})
	// Useful to fill up your ipCache and see how your proxy performs with high memory usage
	case "FILL_IP_CACHE":
		firewall.Mutex.Lock()
		for i := 0; i < 19980; i++ {
			firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
		}
		firewall.Mutex.Unlock()

		APIResponse(writer, true, map[string]interface{}{})
	case "RELOAD":
		if ConfigReloader == nil {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": ERR_ACTION_NOT_FOUND,
			})
			break
		}
		if err := ConfigReloader(); err != nil {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR":        ERR_RELOAD_FAILED,
				"ERROR_DETAIL": err.Error(),
			})
			break
		}
		APIResponse(writer, true, map[string]interface{}{
			"RELOADED": true,
		})
	case "GET_PROXY_FEATURES":
		APIResponse(writer, true, proxyFeaturesResponse())
	case "REFRESH_REPUTATION_FEED":
		started := firewall.RefreshReputationFeedAsync()
		feedConfigured, _, _, _, _, _, _, _, _ := firewall.ReputationStatus()
		APIResponse(writer, true, map[string]interface{}{
			"REFRESH_STARTED": started,
			"FEED_CONFIGURED": feedConfigured,
		})
	case "GET_DOMAINS":
		APIResponse(writer, true, domainsListResponse())
	case "CLEAR_LOGS":
		APIResponse(writer, true, clearAllLogsResponse())
	case "LIST_CONFIG_BACKUPS":
		APIResponse(writer, true, listBackupsResponse())
	case "RESTORE_CONFIG_BACKUP":
		response, errCode, detail := restoreBackupResponse(params)
		if errCode != "" {
			results := map[string]interface{}{
				"ERROR": errCode,
			}
			if detail != "" {
				results["ERROR_DETAIL"] = detail
			}
			APIResponse(writer, false, results)
			return
		}
		APIResponse(writer, true, response)
	default:
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

func handleDomainActions(action string, writer http.ResponseWriter, domainData *domains.DomainData, domainSettings *domains.DomainSettings, params map[string]string) {
	switch action {
	case "GET_TOTAL_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS": domainData.TotalRequests,
		})
	case "GET_BYPASSED_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS": domainData.BypassedRequests,
		})
	case "GET_TOTAL_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsPerSecond,
		})
	case "GET_BYPASSED_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsBypassedPerSecond,
		})
	case "GET_FIREWALL_RULES":
		APIResponse(writer, true, map[string]interface{}{
			"FIREWALL_RULES": domainSettings.RawCustomRules,
		})
	case "GET_LOGS":
		APIResponse(writer, true, map[string]interface{}{
			"LOGS": domainData.LastLogs,
		})
	case "GET_DOMAIN_FEATURES":
		APIResponse(writer, true, domainFeaturesResponse(domainSettings))
	case "GET_ATTACK_REPORT":
		response, errCode := attackReportResponse(domainSettings.Name, domainData, params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "PURGE_CACHE":
		response, errCode := purgeCacheResponse(domainSettings, params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "SET_DOMAIN_FEATURES":
		response, errCode := applyDomainFeatures(domainSettings, params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "GET_STAGE":
		APIResponse(writer, true, stageResponse(domainSettings.Name))
	case "SET_STAGE":
		response, errCode := applyStage(domainSettings.Name, params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "CLEAR_LOGS":
		APIResponse(writer, true, clearLogsResponse(domainSettings.Name))
	case "GET_DOMAIN_CONFIG":
		APIResponse(writer, true, domainConfigResponse(domainSettings))
	case "SET_DOMAIN_CONFIG":
		response, errCode, detail := applyDomainConfig(domainSettings, params)
		if errCode != "" {
			results := map[string]interface{}{
				"ERROR": errCode,
			}
			if detail != "" {
				results["ERROR_DETAIL"] = detail
			}
			APIResponse(writer, false, results)
			return
		}
		APIResponse(writer, true, response)
	case "ADD_RULE", "UPDATE_RULE", "DELETE_RULE":
		var response map[string]interface{}
		var errCode, detail string
		switch action {
		case "ADD_RULE":
			response, errCode, detail = addRule(domainSettings.Name, params)
		case "UPDATE_RULE":
			response, errCode, detail = updateRule(domainSettings.Name, params)
		case "DELETE_RULE":
			response, errCode, detail = deleteRule(domainSettings.Name, params)
		}
		if errCode != "" {
			results := map[string]interface{}{
				"ERROR": errCode,
			}
			if detail != "" {
				results["ERROR_DETAIL"] = detail
			}
			APIResponse(writer, false, results)
			return
		}
		APIResponse(writer, true, response)
	case "SIMULATE_RULE":
		response, errCode, detail := simulateRule(params)
		if errCode != "" {
			results := map[string]interface{}{
				"ERROR": errCode,
			}
			if detail != "" {
				results["ERROR_DETAIL"] = detail
			}
			APIResponse(writer, false, results)
			return
		}
		APIResponse(writer, true, response)
	case "EXPORT_RULES":
		APIResponse(writer, true, exportRules(domainSettings.Name, domainSettings))
	case "IMPORT_RULES":
		response, errCode, detail := importRules(domainSettings.Name, params)
		if errCode != "" {
			results := map[string]interface{}{
				"ERROR": errCode,
			}
			if detail != "" {
				results["ERROR_DETAIL"] = detail
			}
			APIResponse(writer, false, results)
			return
		}
		APIResponse(writer, true, response)
	default:
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

func ProcessV2(w http.ResponseWriter, r *http.Request) bool {

	path := strings.TrimPrefix(r.URL.Path, "/_bProxy/api/v2/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return false
	}

	// Best-effort action/domain for the audit entry on auth
	// failure; the real dispatch below re-derives them.
	auditDomain, auditActionName := "", parts[0]
	if len(parts) > 1 {
		auditDomain, auditActionName = parts[0], parts[1]
	}

	role, ok := proxy.RoleForSecret(r.Header.Get("Proxy-Secret"))
	if !ok {
		auditUnauthenticated(r, auditActionName, auditDomain)
		return false
	}

	// The recorder captures the response so the deferred audit
	// entry can report the real outcome on every return path.
	recorder := &auditRecorder{ResponseWriter: w}
	var action, domain string
	var params map[string]string
	defer func() {
		auditAction(r, role, action, domain, params, recorder.captured)
	}()

	if len(parts) == 1 {

		// /:action

		action, params = parts[0], queryParams(r)
		if known, allowed := authorize(role, action); known && !allowed {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		handleProxyActions(parts[0], recorder, queryParams(r))
		return true
	} else {

		//  /:domain/:action

		action, domain, params = parts[1], parts[0], queryParams(r)
		if known, allowed := authorize(role, action); known && !allowed {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		uncastedDomainSettingsdomain, ok := domains.DomainsMap.Load(parts[0])
		if !ok {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_DOMAIN_NOT_FOUND,
			})
			return true
		}
		domainSettingsdomain, _ := uncastedDomainSettingsdomain.(domains.DomainSettings)

		firewall.Mutex.RLock()
		domainData := domains.DomainsData[parts[0]]
		firewall.Mutex.RUnlock()

		handleDomainActions(parts[1], recorder, &domainData, &domainSettingsdomain, queryParams(r))
		return true
	}
}

func APIResponse(writer http.ResponseWriter, success bool, response map[string]interface{}) error {

	writer.Header().Set("Content-Type", "application/json")

	apiResponse := API_RESPONSE{
		Success:  success,
		Response: response,
	}

	jsonResponse, err := json.Marshal(apiResponse)
	if err != nil {
		return err
	}

	fmt.Fprint(writer, string(jsonResponse))
	return nil
}
