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

// SSOSessionValidator, when set by the server package, checks a
// request's SSO session cookie and reports the session's role.
// It mirrors the ConfigReloader hook pattern: the api package
// cannot import the server package, so the server registers the
// validator at startup. Nil means SSO cookie auth is
// unavailable (the server package always sets it, so nil only
// in tests that do not import the server).
var SSOSessionValidator func(r *http.Request) (role string, ok bool)

// attemptSSOAuth validates an SSO session cookie for an API
// call. It reports (role, true, false) only when the cookie is
// valid AND the CSRF header is present; a valid cookie without
// the header reports csrfMissing so the caller can answer 403
// rather than falling through to the backend.
func attemptSSOAuth(request *http.Request) (role string, ok bool, csrfMissing bool) {
	if SSOSessionValidator == nil {
		return "", false, false
	}
	role, ok = SSOSessionValidator(request)
	if !ok {
		return "", false, false
	}
	if request.Header.Get(proxy.SSOCSRFHeader) != "1" {
		return "", false, true
	}
	return role, true, false
}

// AuthenticatedControlRequest reports whether r is a control-plane
// request (API v1, API v2, or the dashboard) carrying valid
// authentication: a known API secret (the main apisecret or a
// role secret) in the version's secret header, or a valid SSO
// session cookie plus the CSRF header. The dashboard path is
// authenticated by the path itself, which contains the admin
// secret, exactly as the reserved-path handler treats it.
//
// The middleware uses this to exempt authenticated control-plane
// requests from the challenge flow: at a locked Stage 2/3 a
// scripted client cannot solve a challenge, so without the
// exemption even the unlock call is answered with a challenge
// page. A valid SSO cookie WITHOUT the CSRF header does not
// count: such a call falls through to the normal flow, where
// Process/ProcessV2 answer 403 exactly as before. Any other
// request (missing or wrong secret, non-control-plane path)
// reports false and keeps the current fall-through/challenge
// behavior unchanged.
func AuthenticatedControlRequest(request *http.Request) bool {
	path := request.URL.Path
	if proxy.AdminSecret != "" {
		if path == "/_bProxy/"+proxy.AdminSecret+"/api/v1" {
			if _, _, ok := proxy.ScopeForSecret(request.Header.Get("proxy-secret")); ok {
				return true
			}
			_, ok, _ := attemptSSOAuth(request)
			return ok
		}
		if path == "/_bProxy/"+proxy.AdminSecret+"/dashboard" {
			return true
		}
	}
	if strings.HasPrefix(path, "/_bProxy/api/v2") {
		if _, _, ok := proxy.ScopeForSecret(request.Header.Get("Proxy-Secret")); ok {
			return true
		}
		_, ok, _ := attemptSSOAuth(request)
		return ok
	}
	return false
}

func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	role, tenant, ok := proxy.ScopeForSecret(request.Header.Get("proxy-secret"))
	ssoAuthed := false

	// The recorder captures the response so the deferred audit
	// entry can report the real outcome on every return path.
	recorder := &auditRecorder{ResponseWriter: writer}
	var action, domain string
	var params map[string]string
	defer func() {
		auditAction(request, role, action, domain, params, recorder.captured)
	}()

	// SSO session fallback (Batch 5): a valid session cookie
	// authenticates dashboard API calls without the API secret.
	// The check runs after the recorder is set up so a CSRF
	// rejection is audited like any other outcome. A valid
	// cookie without the CSRF header is answered 403, never
	// fallen through to the backend.
	if !ok {
		ssoRole, ssoOK, csrfMissing := attemptSSOAuth(request)
		if csrfMissing {
			role = "unauthenticated"
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		if !ssoOK {
			auditUnauthenticated(request, "", "")
			return false
		}
		role, tenant, ssoAuthed = ssoRole, "", true
	}

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
	known, allowed := authorize(role, action)
	if known && !allowed {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_FORBIDDEN,
		})
		return true
	}
	// Tenant scoping (Batch 5): a tenant-scoped caller may run
	// only GET_DOMAINS and GET_TENANT_USAGE as proxy actions.
	// Domain actions are checked against the domain's tenant
	// after the settings load below.
	if known && tenant != "" && apiRequest.Domain == "" && !tenantProxyActionAllowed(action) {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_FORBIDDEN,
		})
		return true
	}
	if tenant != "" {
		// The deferred audit entry reports the scope.
		role = role + " (tenant " + tenant + ")"
	}
	if ssoAuthed {
		// The deferred audit entry reports the auth method.
		role = role + " (sso)"
	}

	if apiRequest.Domain == "" {
		handleProxyActions(apiRequest.Action, recorder, apiRequest.Params, tenant)
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

	if tenant != "" && domains.NormalizeTenant(domainSettings.Tenant) != domains.NormalizeTenant(tenant) {
		APIResponse(recorder, false, map[string]interface{}{
			"ERROR": ERR_FORBIDDEN,
		})
		return true
	}

	handleDomainActions(apiRequest.Action, recorder, &domainData, &domainSettings, apiRequest.Params)
	return true
}

func handleProxyActions(action string, writer http.ResponseWriter, params map[string]string, tenantScope string) {
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
		APIResponse(writer, true, domainsListResponse(tenantScope))
	case "GET_TENANTS":
		APIResponse(writer, true, tenantsListResponse())
	case "GET_TENANT_USAGE":
		response, errCode := tenantUsageResponse(params, tenantScope)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "CLEAR_LOGS":
		APIResponse(writer, true, clearAllLogsResponse())
	case "LIST_CONFIG_BACKUPS":
		APIResponse(writer, true, listBackupsResponse())
	case "SEARCH_LOGS":
		response, errCode := searchLogsResponse("", params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "GET_ATTACK_MAP":
		APIResponse(writer, true, attackMapResponse(params))
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
	case "GET_IP_LISTS":
		APIResponse(writer, true, ipListsResponse(domainSettings))
	case "SEARCH_LOGS":
		response, errCode := searchLogsResponse(domainSettings.Name, params)
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
			return
		}
		APIResponse(writer, true, response)
	case "ADD_IP_ENTRY", "REMOVE_IP_ENTRY":
		var response map[string]interface{}
		var errCode string
		if action == "ADD_IP_ENTRY" {
			response, errCode = applyIPEntry(domainSettings, params)
		} else {
			response, errCode = removeIPEntry(domainSettings, params)
		}
		if errCode != "" {
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": errCode,
			})
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

	role, tenant, ok := proxy.ScopeForSecret(r.Header.Get("Proxy-Secret"))
	ssoAuthed := false

	// The recorder captures the response so the deferred audit
	// entry can report the real outcome on every return path.
	recorder := &auditRecorder{ResponseWriter: w}
	var action, domain string
	var params map[string]string
	defer func() {
		auditAction(r, role, action, domain, params, recorder.captured)
	}()

	// SSO session fallback (Batch 5): see Process. A valid
	// cookie without the CSRF header is answered 403, never
	// fallen through to the backend.
	if !ok {
		ssoRole, ssoOK, csrfMissing := attemptSSOAuth(r)
		if csrfMissing {
			role = "unauthenticated"
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		if !ssoOK {
			auditUnauthenticated(r, auditActionName, auditDomain)
			return false
		}
		role, tenant, ssoAuthed = ssoRole, "", true
	}

	if len(parts) == 1 {

		// /:action

		action, params = parts[0], queryParams(r)
		known, allowed := authorize(role, action)
		if known && !allowed {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		// Tenant scoping (Batch 5): a tenant-scoped caller may
		// run only GET_DOMAINS and GET_TENANT_USAGE here.
		if known && tenant != "" && !tenantProxyActionAllowed(action) {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		if tenant != "" {
			role = role + " (tenant " + tenant + ")"
		}
		if ssoAuthed {
			role = role + " (sso)"
		}
		handleProxyActions(parts[0], recorder, queryParams(r), tenant)
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

		// Tenant scoping (Batch 5): the domain must belong to
		// the caller's tenant.
		if tenant != "" && domains.NormalizeTenant(domainSettingsdomain.Tenant) != domains.NormalizeTenant(tenant) {
			APIResponse(recorder, false, map[string]interface{}{
				"ERROR": ERR_FORBIDDEN,
			})
			return true
		}
		if tenant != "" {
			role = role + " (tenant " + tenant + ")"
		}

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
