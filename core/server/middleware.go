package server

import (
	"bytes"
	"sonushield/core/api"
	"sonushield/core/dashboard"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/metrics"
	"sonushield/core/proxy"
	"sonushield/core/utils"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kor44/gofilter"
)

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

func Middleware(writer http.ResponseWriter, request *http.Request) {

	// defer pnc.PanicHndl() we wont do this during prod, to avoid overhead

	buffer := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buffer)
	buffer.Reset()

	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	//Request-smuggling guard (Batch 5, defence in depth). Go's
	//server rejects or normalises ambiguous framing (duplicate
	//Content-Length, Content-Length together with
	//Transfer-Encoding) before handlers run, so this check is
	//expected never to fire; if both forms somehow survive
	//parsing, the request is rejected rather than proxied with
	//an ambiguous body length.
	if len(request.TransferEncoding) > 0 && request.ContentLength > 0 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		SendResponse("Bad request.", buffer, writer)
		return
	}

	// Prometheus metrics (Batch 2). Secret-gated like the dashboard and
	// API, served only when metricsEnabled is set, and handled before
	// any challenge or rate limiting so scrapes are neither challenged
	// nor counted in request statistics. When disabled, the request
	// falls through to the normal flow exactly as before.
	if metrics.IsMetricsRequest(request) {
		metrics.ServeMetrics(writer)
		return
	}

	//Public status page (Batch 5). Opt-in via proxy.statusPage,
	//handled before any challenge or rate limiting, like metrics.
	//When disabled, the request falls through exactly as before.
	if IsStatusRequest(request) {
		ServeStatus(writer)
		return
	}

	// Bare liveness check for scrubbing providers and load
	// balancers (Batch 5). Same opt-in flag as the status
	// page, same early handling, no data beyond ok.
	if IsHealthRequest(request) {
		ServeHealth(writer)
		return
	}

	// SSO/OIDC login (Batch 5). Handled before challenge and
	// rate limiting like metrics and the status page, so an
	// unauthenticated visitor can sign in. Unhandled requests
	// (SSO disabled, or any other path) fall through exactly
	// as before.
	if HandleSSO(writer, request) {
		return
	}

	// Authenticated control-plane requests (Batch 6). API and
	// dashboard requests carrying a valid secret bypass the
	// challenge flow entirely: at a locked Stage 2/3 a scripted
	// client cannot solve a challenge, so without this exemption
	// even the unlock call itself is answered with a challenge
	// page. Requests with a missing or wrong secret fall through
	// to the normal flow exactly as before (challenged or proxied
	// like any other request), and non-control-plane paths are
	// unaffected. Like metrics, exempt requests are neither
	// challenged nor counted in request statistics; the API
	// handlers audit them exactly as they do on the late path.
	// If a handler declines (a secret changed mid-flight), the
	// request falls through to the normal flow below.
	if api.AuthenticatedControlRequest(request) {
		firewall.Mutex.RLock()
		earlyData := domains.DomainsData[domainName]
		firewall.Mutex.RUnlock()
		//PWA shell assets (Batch 6): same exemption as the
		//dashboard page, so the installed app shell loads even
		//at a locked stage.
		if dashboard.ServeAsset(writer, request.URL.Path, proxy.AdminSecret) {
			return
		}
		switch request.URL.Path {
		case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
			if api.Process(writer, request, earlyData) {
				return
			}
		case "/_bProxy/" + proxy.AdminSecret + "/dashboard":
			dashboard.Serve(writer, proxyBranding())
			return
		}
		if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
			if api.ProcessV2(writer, request) {
				return
			}
		}
		if strings.HasPrefix(request.URL.Path, "/_bProxy/public/") {
			if api.ProcessPublic(writer, request) {
				return
			}
		}
	}

	// Log paths must never carry the admin secret, which is a path
	// segment of the API, dashboard, and metrics routes. Redact it
	// once here; every structured-log entry below uses logPath.
	logPath := request.URL.Path
	if proxy.AdminSecret != "" {
		if rest, ok := strings.CutPrefix(logPath, "/_bProxy/"+proxy.AdminSecret); ok {
			logPath = "/_bProxy/[redacted]" + rest
		}
	}

	var ip string
	var tlsFp string
	var ja4Fp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	if domains.Config.Proxy.Cloudflare {

		ip = request.Header.Get("Cf-Connecting-Ip")

		tlsFp = "Cloudflare"
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.Mutex.RLock()
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.RUnlock()
	} else {
		ip = strings.Split(request.RemoteAddr, ":")[0]

		//Retrieve information about the client
		firewall.Mutex.RLock()
		tlsFp = firewall.Connections[request.RemoteAddr]
		ja4Fp = firewall.ConnectionsJA4[request.RemoteAddr]
		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.RUnlock()

		//Read-Only IMPORTANT: Must be put in mutex if you add the ability to change indexed fingerprints while program is running
		browser = firewall.KnownFingerprints[tlsFp]
		botFp = firewall.BotFingerprints[tlsFp]

		//JA4 fills in only when the legacy fingerprint is unknown, so the
		//legacy lists stay the primary signal. JA4 lists are empty by
		//default; see global/fingerprints/SOURCES.md.
		if ja4Fp != "" {
			if browser == "" {
				browser = firewall.KnownJA4[ja4Fp]
			}
			if botFp == "" {
				botFp = firewall.BotJA4[ja4Fp]
			}
		}
	}

	firewall.Mutex.Lock()
	// Leaving this here for future reference. When the monitor thread that's supposed to prefill these maps lags
	//behind for some reason, this will be come really messy. The mutex will be locked and never unlocked again,
	//freezing the entire proxy
	/*_, temp_found := firewall.WindowAccessIps[proxy.Last10SecondTimestamp]
	if !temp_found {
		log.Printf("Attempting To Set %s, %d but timestamp hasn't been set yet ?!?", ip, proxy.Last10SecondTimestamp)
	}*/
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	if !quietMode() {
		writer.Header().Set("SonuShield", "1.5")
	}

	//SyncMap because semi-readonly. Loaded here (before the
	//early blocks) so the per-domain IP lists can allow or block
	//before rate limiting runs.
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

	//IP allow/block lists (Batch 5). A blocklisted IP is blocked
	//immediately; an allowlisted IP starts at susLv 0 and bypasses
	//the early rate-limit and fingerprint blocks below. The block
	//list wins when an IP matches both. Empty lists match nothing.
	ipAllowlisted, ipBlocklisted := domainSettings.IPListMatch(ip)
	if ipBlocklisted {
		writer.Header().Set("Content-Type", "text/plain")
		metrics.ObserveBlock(domainName, "ip_blocklist")
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "ip_blocklist", Rule: "IPBL", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		SendResponse(blockMessage("Forbidden."), buffer, writer)
		return
	}
	if ipAllowlisted {
		susLv = 0
	}

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if !ipAllowlisted && ipCountCookie > proxy.FailChallengeRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		metrics.ObserveBlock(domainName, "ratelimit")
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "ratelimit", Rule: "R1", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Stage: domainData.Stage, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		SendResponse(blockMessage("You have been ratelimited. (R1)"), buffer, writer)
		return
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if !ipAllowlisted && ipCount > proxy.IPRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		metrics.ObserveBlock(domainName, "ratelimit")
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "ratelimit", Rule: "R2", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Stage: domainData.Stage, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		SendResponse(blockMessage("You have been ratelimited. (R2)"), buffer, writer)
		return
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if !ipAllowlisted && fpCount > proxy.FPRatelimit {
			writer.Header().Set("Content-Type", "text/plain")
			metrics.ObserveBlock(domainName, "ratelimit")
			logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "ratelimit", Rule: "R3", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Stage: domainData.Stage, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			SendResponse(blockMessage("You have been ratelimited. (R3)"), buffer, writer)
			return
		}

		firewall.Mutex.Lock()
		firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
		firewall.Mutex.Unlock()
	}

	//Block user-specified fingerprints (legacy list first, JA4 second)
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp == "" && ja4Fp != "" {
		forbiddenFp = firewall.ForbiddenJA4[ja4Fp]
	}
	if forbiddenFp != "" && !ipAllowlisted {
		writer.Header().Set("Content-Type", "text/plain")
		metrics.ObserveBlock(domainName, "fingerprint")
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "fingerprint", Rule: forbiddenFp, Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		SendResponse(blockMessage("Your browser "+forbiddenFp+" is not allowed."), buffer, writer)
		return
	}

	//Challenge-provider verification (Turnstile/hCaptcha). Handled before
	//the cookie check below: the client has no verification cookie yet.
	//A reserved /_bProxy/ path like /_bProxy/verified, not a management
	//page; it only answers POSTs carrying a valid single-use nonce.
	if HandleChallengeVerify(writer, request, ip, tlsFp) {
		return
	}

	//Memory-hard proof-of-work verification. Same placement and
	//reasoning as the provider verification above: the client has
	//no verification cookie yet, so this runs before the cookie
	//check below.
	if HandleMemoryPowVerify(writer, request, ip, tlsFp) {
		return
	}

	//Mouse/scroll behavior beacon (Batch 7). Same placement:
	//the client reports interaction facts from a challenge
	//page, before it holds a verification cookie. Answers
	//404 unless the domain enabled behaviorCheck.
	if HandleBehaviorBeacon(writer, request, domainName, ip, domainSettings) {
		return
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

	reqUa := request.UserAgent()

	//Geo/ASN lookup, hoisted here so the risk score and the firewall
	//rules share one result. Zero values when no database is
	//configured, so rules simply do not match on these fields. In
	//Cloudflare mode the CF-IPCountry header is authoritative and
	//wins over the database for the country; the ASN still comes
	//from the database.
	geoCountry, geoASN := firewall.LookupGeo(ip)
	if domains.Config.Proxy.Cloudflare {
		if cfCountry := request.Header.Get("CF-IPCountry"); cfCountry != "" {
			geoCountry = cfCountry
		}
	}

	//IP reputation lookup, hoisted for the same reason: the risk
	//score, the firewall rules, and the post-rule bump all use this
	//one result.
	repListed := firewall.LookupReputation(ip)

	//Cross-domain reputation (Batch 5). Opted-in domains share
	//recent blocks: a client blocked on another opted-in domain is
	//looked up here, feeds the risk score below, and gets its
	//suspicion bumped after the score is computed. Skipped for
	//domains that did not opt in.
	sharedRep := false
	if domainSettings.ShareReputation {
		sharedRep = firewall.LookupSharedReputation(ip, tlsFp)
	}

	//CORS preflight (Batch 5). Answered directly, without
	//challenge, when the domain configures CORS: browsers send
	//preflights without credentials, so challenging them would
	//break cross-origin access entirely. Unconfigured domains
	//are unaffected.
	if HandlePreflight(writer, request, domainSettings.CORS) {
		return
	}

	//Payload size limit (Batch 5). Requests whose declared body
	//exceeds the effective limit are rejected with a clean 413
	//before any evaluation work; chunked bodies (unknown length)
	//are capped with MaxBytesReader as a backstop and fail while
	//being proxied. See domains.BodyLimitFor for the resolution
	//order and the documented default.
	if limit := domainSettings.BodyLimitFor(request.URL.Path); limit >= 0 {
		if request.ContentLength > limit {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			metrics.ObserveBlock(domainName, "payload")
			logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "payload_limit", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			SendResponse("Request entity too large.", buffer, writer)
			return
		}
		if request.Body != nil && (request.ContentLength < 0 || len(request.TransferEncoding) > 0) {
			request.Body = http.MaxBytesReader(writer, request.Body, limit)
		}
	}

	//Timing and velocity detection (Batch 5). Log-only by
	//default: a flagged IP gets a rate-limited log entry and a
	//risk-score contribution, but no outcome change. Enforcement
	//(a suspicion bump) is opt-in per domain.
	timingVerdict := firewall.ObserveTiming(ip)

	//Mouse/scroll behavior signal (Batch 7). Consulted only
	//when the domain enabled behaviorCheck; the beacon only
	//runs on challenge pages the proxy itself serves.
	behaviorVerdict, behaviorLogThis := "", false
	if domainSettings.BehaviorCheck {
		behaviorVerdict, behaviorLogThis = firewall.BehaviorVerdict(domainName, ip)
	}

	//Composite risk score (Batch 5). A snapshot of the signals
	//known at evaluation time; see firewall/risk.go for the
	//weights. It is a firewall rule field (ip.risk), is carried in
	//structured logs, and feeds the per-domain aggregates used by
	//attack reports. Same-request honeypot and fake-bot hits raise
	//susLv after this point and are not reflected in it.
	riskScore := firewall.ComputeRiskScore(firewall.RiskInputs{
		SusLevel:           susLv,
		KnownBrowser:       browser != "",
		BotListed:          botFp != "",
		UnknownFingerprint: browser == "" && botFp == "" && tlsFp != "",
		ReputationListed:   repListed,
		SharedReputation:   sharedRep,
		TimingAnomaly:      timingVerdict.Anomaly,
		BehaviorBot:        behaviorVerdict == "bot",
		ChallengeFailures:  ipCountCookie,
		Country:            geoCountry,
		ASN:                geoASN,
		HighRiskCountries:  domainSettings.RiskHighRiskCountries,
		HighRiskASNs:       domainSettings.RiskHighRiskASNs,
	})

	firewall.Mutex.Lock()
	domainData = domains.DomainsData[domainName]
	domainData.RiskSum += int64(riskScore)
	domainData.RiskCount++
	if riskScore > domainData.RiskMax {
		domainData.RiskMax = riskScore
	}
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	if timingVerdict.Anomaly {
		if timingVerdict.LogThis {
			logging.Log(logging.Entry{Event: "timing", Domain: domainName, IP: ip, Action: "timing_" + timingVerdict.Kind, Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		}
		if domainSettings.TimingEnforce {
			timingBump := domainSettings.TimingSusLv
			if timingBump <= 0 {
				timingBump = 1
			}
			susLv += timingBump
		}
	}

	if behaviorVerdict == "bot" {
		if behaviorLogThis {
			logging.Log(logging.Entry{Event: "behavior", Domain: domainName, IP: ip, Action: "behavior_bot", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		}
		if domainSettings.BehaviorEnforce {
			behaviorBump := domainSettings.BehaviorSusLv
			if behaviorBump <= 0 {
				behaviorBump = 1
			}
			susLv += behaviorBump
		}
	}

	if sharedRep {
		susLv += firewall.SharedReputationBump(domainSettings.SharedReputationSusLv)
		logging.Log(logging.Entry{Event: "sharedrep", Domain: domainName, IP: ip, Action: "shared_reputation", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
	}

	//WAF-lite inspection. Log-only by default (matches are logged, the
	//request continues); block mode answers with a generic unbranded
	//403. Runs after the challenge-verify hook so verification POSTs
	//are not scanned, and before firewall rules so blocks are cheap.
	wafBlocked, wafRule := firewall.CheckRequest(request, domainSettings.WAFMode, domainSettings.WAFInspectBody, domainSettings.WAFWpLoginLimit, ip)
	if wafRule != "" {
		metrics.ObserveWAFMatch(domainName, wafRule)
		wafEvent, wafAction := "waf", "waf_log"
		if wafBlocked {
			wafEvent, wafAction = "block", "waf"
		}
		logging.Log(logging.Entry{Event: wafEvent, Domain: domainName, IP: ip, Action: wafAction, Rule: wafRule, Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
	}
	if wafBlocked {
		if domainSettings.ShareReputation {
			firewall.RecordSharedReputation(ip, tlsFp, domainName)
		}
		metrics.ObserveBlock(domainName, "waf")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		SendResponse("Forbidden.", buffer, writer)
		return
	}

	//Honeypot endpoints. A request for an operator-configured decoy
	//path raises suspicion; legitimate visitors never request these
	//paths, and with no paths configured this is a no-op.
	if firewall.HoneypotHit(domainSettings.HoneypotPaths, request.URL.Path) {
		susLv += firewall.HoneypotBump(domainSettings.HoneypotSusLv)
		logging.Log(logging.Entry{Event: "honeypot", Domain: domainName, IP: ip, Action: "honeypot", Rule: logPath, Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
	}

	//Canary tokens (Batch 7). A request that uses an
	//operator-configured decoy path or credential is blocked
	//immediately at maximum suspicion: no legitimate visitor
	//ever touches a decoy. The notice never includes a token
	//value. With nothing configured this is a no-op.
	if canaryMatch, canaryHit := firewall.CheckCanary(request, domainSettings.CanaryPaths, domainSettings.CanaryTokens); canaryHit {
		if domainSettings.ShareReputation {
			firewall.RecordSharedReputation(ip, tlsFp, domainName)
		}
		metrics.ObserveBlock(domainName, "canary")
		logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "canary_" + canaryMatch.Kind, Rule: canaryMatch.Path, Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		if firewall.CanaryShouldAlert(ip) {
			settingsCopy := domainSettings
			go utils.SendNotice(settingsCopy, "Canary token tripped on "+domainName, "A "+canaryMatch.Kind+" decoy was used from IP "+ip+" on path "+canaryMatch.Path+". The request was blocked. No token value is included in this notice.")
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		SendResponse("Forbidden.", buffer, writer)
		return
	}

	//Fake search-bot verification. Only when the operator enabled
	//it: a claimed Googlebot/Bingbot that DNS does not confirm
	//raises suspicion. DNS failures fail open ("unchecked") and add
	//nothing. The classification is also a firewall rule field.
	searchBot := ""
	if domainSettings.FakeBotCheck {
		searchBot = firewall.ClassifySearchBot(ip, reqUa)
		if searchBot == "fake" {
			susLv += firewall.FakeBotBump(domainSettings.FakeBotSusLv)
			logging.Log(logging.Entry{Event: "fakebot", Domain: domainName, IP: ip, Action: "fake_bot", Fingerprint: tlsFp, JA4: ja4Fp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
		}
	}

	httpFp := firewall.ComputeHTTPFingerprint(request)
	h2Fp := firewall.ComputeHTTP2Fingerprint(request)
	//Passive OS fingerprinting (Batch 7): signals observed at
	//accept time, classified only against operator signatures.
	osSignals := firewall.SignalsFor(request.RemoteAddr)
	osLabel := firewall.ClassifyOS(osSignals)
	tcpInfoStr := osSignals.String()
	//QUIC fingerprint: always empty until Batch 3 adds a QUIC
	//listener; the field is reserved, not populated. See
	//firewall/quic.go.
	quicFp := firewall.ComputeQUICFingerprint(request)
	//repListed was computed above, next to the risk score.
	repValue := ""
	if repListed {
		repValue = "listed"
	}

	// Matched firewall rules, for structured logging only. Computed
	// below when logging is enabled; empty otherwise.
	matchedRules := []string{}

	//Edge rules (Batch 6) run before the general firewall rules,
	//as if prepended to the list: a set action in the edge chain
	//stops general evaluation. The message is built when either
	//list is non-empty.
	if len(domainSettings.CustomRules) != 0 || len(domainSettings.EdgeRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.country":            geoCountry,
			"ip.asn":                geoASN,
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.ja4":                ja4Fp,
			"ip.quic":               quicFp,
			"ip.os":                 osLabel,
			"ip.tcpinfo":            tcpInfoStr,
			"ip.behavior":           behaviorVerdict,
			"ip.reputation":         repValue,
			"ip.searchbot":          searchBot,
			"ip.risk":               riskScore,
			"ip.timing":             timingVerdict.Kind,
			"ip.http_requests":      ipCount,
			"ip.challenge_requests": ipCountCookie,

			"http.host":       domainName,
			"http.version":    request.Proto,
			"http.method":     request.Method,
			"http.url":        request.RequestURI,
			"http.query":      request.URL.RawQuery,
			"http.path":       request.URL.Path,
			"http.user_agent": strings.ToLower(reqUa),
			"http.cookie":      request.Header.Get("Cookie"),
			"http.fingerprint": httpFp,
			"http.http2":       h2Fp,

			"proxy.stage":         domainData.Stage,
			"proxy.cloudflare":    domains.Config.Proxy.Cloudflare,
			"proxy.stage_locked":  domainData.StageManuallySet,
			"proxy.attack":        domainData.RawAttack,
			"proxy.bypass_attack": domainData.BypassAttack,
			"proxy.rps":           domainData.RequestsPerSecond,
			"proxy.rps_allowed":   domainData.RequestsBypassedPerSecond,
		}

		if domainSettings.RulesDryRun {
			//Dry-run mode (Batch 4): rules are evaluated and
			//matches logged, but susLv is left unchanged, so
			//no request is challenged or blocked by rules.
			wouldBe, edgeStopped := firewall.EvalEdgeRules(domainSettings, requestVariables, susLv)
			if !edgeStopped {
				wouldBe = firewall.EvalFirewallRule(domainSettings, requestVariables, wouldBe)
			}
			dryMatched := append(firewall.MatchedEdgeRules(domainSettings, requestVariables), firewall.MatchedRules(domainSettings, requestVariables)...)
			if len(dryMatched) > 0 {
				logging.Log(logging.Entry{Event: "dryrun", Domain: domainName, IP: ip, Action: "dryrun", Rules: dryMatched, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, WouldBeSusLevel: wouldBe, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			}
			matchedRules = dryMatched
		} else {
			var edgeStopped bool
			susLv, edgeStopped = firewall.EvalEdgeRules(domainSettings, requestVariables, susLv)
			if !edgeStopped {
				susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)
			}
			if logging.Enabled() {
				matchedRules = append(firewall.MatchedEdgeRules(domainSettings, requestVariables), firewall.MatchedRules(domainSettings, requestVariables)...)
			}
		}
	}

	//IP reputation applies after firewall rules, whether or not the domain
	//has rules. Listed IPs get a harder challenge; unlisted IPs are
	//unaffected and nothing is configured by default.
	if repListed {
		susLv += firewall.ReputationBump()
	}

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	encryptedIP := ""
	hashedEncryptedIP := ""
	susLvStr := utils.StageToString(susLv)
	accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)

	if !encryptedExists {
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(accessKey, proxy.CookieOTP)
		case 2:
			encryptedIP = utils.Encrypt(accessKey, proxy.JSOTP)
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.CaptchaOTP)
		default:
			writer.Header().Set("Content-Type", "text/plain")
			metrics.ObserveBlock(domainName, "suspect")
			logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "suspect", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			if domainSettings.ShareReputation {
				firewall.RecordSharedReputation(ip, tlsFp, domainName)
			}
			domainSettings.Tarpit.Apply(susLv)
			SendResponse(blockMessage("Suspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")"), buffer, writer)
			return
		}
		firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)
	} else {
		encryptedIP = encryptedCache.(string)
		cachedHIP, foundCachedHIP := firewall.CacheIps.Load(encryptedIP)
		if foundCachedHIP {
			hashedEncryptedIP = cachedHIP.(string)
		}
	}

	//Check if client provided correct verification result
	//Public API requests skip the challenge switch below:
	//the dispatch after this block answers them with JSON
	//errors at any stage. The suspect block above, for
	//susLv > 3, still applies to every path.
	publicAPI := strings.HasPrefix(request.URL.Path, "/_bProxy/public/")
	if !publicAPI && !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {

		firewall.Mutex.Lock()
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++
		firewall.Mutex.Unlock()

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			metrics.ObserveChallenge(domainName, 1)
			logging.Log(logging.Entry{Event: "challenge", Domain: domainName, IP: ip, Action: "challenge", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
			return
		case 2:
			metrics.ObserveChallenge(domainName, 2)
			logging.Log(logging.Entry{Event: "challenge", Domain: domainName, IP: ip, Action: "challenge", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			//Challenge rotation (Batch 6). When the operator configured
			//a rotation policy, the current wave's (or request's)
			//challenge type decides, and the fixed chain below is
			//skipped. Rotation always serves something when enabled.
			if serveRotatedChallenge(writer, request, domainSettings, domainData, domainName, encryptedIP, hashedEncryptedIP, ip, tlsFp, reqUa, buffer) {
				return
			}

			//Challenge provider (Turnstile/hCaptcha) replaces the
			//proof-of-work page when the operator configured one with
			//their own keys. Falls back to proof-of-work when the
			//provider is not configured or nonce generation fails.
			if ChallengeProviderConfigured(domainSettings) {
				if ServeProviderChallenge(writer, request, domainSettings, domainName, encryptedIP, ip, tlsFp, reqUa) {
					return
				}
			}

			//Memory-hard proof-of-work (Batch 6). Replaces the
			//classic hash puzzle when the operator enables it; the
			//provider challenge above takes precedence. Falls back
			//to the classic puzzle when nonce generation fails.
			if domainSettings.MemoryHardPow {
				if ServeMemoryPowChallenge(writer, request, domainSettings, domainName, encryptedIP, ip, tlsFp, reqUa) {
					return
				}
			}

			serveClassicPowChallenge(writer, request, domainSettings, domainData, domainName, encryptedIP, hashedEncryptedIP, buffer)
			return
		case 3:
			metrics.ObserveChallenge(domainName, 3)
			logging.Log(logging.Entry{Event: "challenge", Domain: domainName, IP: ip, Action: "challenge", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			serveCaptchaChallenge(writer, request, domainSettings, domainName, encryptedIP, ip, buffer)
			return
		default:
			writer.Header().Set("Content-Type", "text/plain")
			metrics.ObserveBlock(domainName, "suspect")
			logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "suspect", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
			if domainSettings.ShareReputation {
				firewall.RecordSharedReputation(ip, tlsFp, domainName)
			}
			domainSettings.Tarpit.Apply(susLv)
			SendResponse(blockMessage("Suspicious request of level "+susLvStr), buffer, writer)
			return
		}
	}

	//Public API v1 (Batch 6): answer here, before access
	//logging, so unauthenticated probes never inflate the
	//bypass counters. Valid keys were already served by the
	//early dispatch; this site answers the rest with JSON
	//401/404/405 errors at any stage. ProcessPublic never
	//proxies and never sets cookies.
	if strings.HasPrefix(request.URL.Path, "/_bProxy/public/") {
		if api.ProcessPublic(writer, request) {
			return
		}
	}

	//Per-session rate limit (Batch 5). Keyed to the challenge
	//cookie, so one abusive session behind shared NAT is limited
	//without punishing every user on that IP. Disabled (0) by
	//default; requests without a session cookie are unaffected.
	if domainSettings.SessionRatelimit > 0 {
		if sessionKey := firewall.SessionKeyFromRequest(request); sessionKey != "" {
			if !firewall.SessionCheck(sessionKey, domainSettings.SessionRatelimit, proxy.RatelimitWindow) {
				writer.Header().Set("Content-Type", "text/plain")
				metrics.ObserveBlock(domainName, "session_ratelimit")
				logging.Log(logging.Entry{Event: "block", Domain: domainName, IP: ip, Action: "session_ratelimit", Rule: "R4", Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent()})
				SendResponse(blockMessage("You have been ratelimited. (R4)"), buffer, writer)
				return
			}
		}
	}

	//Access logs of clients that passed the challenge
	firewall.Mutex.Lock()
	utils.AddLogs(domains.DomainLog{
		Time:      proxy.LastSecondTimeFormated,
		IP:        ip,
		BrowserFP: browser,
		BotFP:     botFp,
		TLSFP:     tlsFp,
		Useragent: reqUa,
		Path:      request.RequestURI,
	}, domainName)

	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	// Structured log for requests that passed the challenge. Logged
	// after the mutex is released; nothing here takes the firewall
	// lock, so the log write can never stall request handling on it.
	logging.Log(logging.Entry{Event: "allow", Domain: domainName, IP: ip, Action: "allow", Rules: matchedRules, Fingerprint: tlsFp, JA4: ja4Fp, HTTPFingerprint: httpFp, Engine: browser, Bot: botFp, Stage: domainData.Stage, SusLevel: susLv, RiskScore: riskScore, Method: request.Method, Path: logPath, UserAgent: request.UserAgent(), RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})

	//Reserved proxy-paths

	//PWA shell assets (Batch 6): served under the same
	//admin-secret path as the dashboard page itself.
	if dashboard.ServeAsset(writer, request.URL.Path, proxy.AdminSecret) {
		return
	}

	switch request.URL.Path {
	case "/_bProxy/stats":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_bProxy/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp+"\nJA4: "+ja4Fp+"\nHTTP Fingerprint: "+httpFp+"\nHTTP/2: "+h2Fp+"\nOS: "+osLabel+"\nTCP Info: "+tcpInfoStr, buffer, writer)
		return
	case "/_bProxy/verified":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("verified", buffer, writer)
		return
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(writer, request, domainData)
		if result {
			return
		}

	case "/_bProxy/" + proxy.AdminSecret + "/dashboard":
		// Dashboard page, gated by the admin-secret path exactly like the
		// v1 API route above. Refuse to serve it when no admin secret is
		// configured, so the page can never become unauthenticated.
		if proxy.AdminSecret == "" {
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("404 Not Found", buffer, writer)
			return
		}
		dashboard.Serve(writer, proxyBranding())
		return

	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("SonuShield; Lightweight http anti-ddos reverse-proxy https://github.com/sonudigitalmindset-design/SonuShield. Originally balooProxy by 41Baloo: https://github.com/41Baloo/balooProxy. Licensed under the GNU General Public License v3.0.", buffer, writer)
		return
	}

	if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
		result := api.ProcessV2(writer, request)
		if result {
			return
		}
	}

	//Edge cache lookup. A fresh cached response is served with the
	//standard Age header; a miss falls through to the backend
	//exactly as before. Only plain GETs without Authorization are
	//ever served from the cache.
	if domainSettings.Cache != nil && request.Method == http.MethodGet && request.Header.Get("Authorization") == "" && !isUpgradeRequest(request) {
		if serveCachedResponse(writer, request, domainSettings, domainName, domains.CacheKey(request)) {
			return
		}
	}

	//Waiting room. When enabled and bypassed traffic is over the
	//threshold, excess visitors queue fairly instead of being
	//dropped. Reserved paths and cached responses already returned
	//above, so only backend-bound traffic is ever queued.
	if domainSettings.Waiting != nil {
		waitingTpl := ""
		if domainSettings.PageTemplates != nil {
			waitingTpl = domainSettings.PageTemplates.WaitingRoom
		}
		if checkWaitingRoom(writer, request, ip, domainSettings.Waiting, domainData.RequestsBypassedPerSecond, waitingTpl, resolveBranding(domainSettings)) {
			return
		}
	}

	//Allow backend to read client information
	//Origin lock (Batch 5). Any client-sent lock header is
	//stripped first so it can never be spoofed; the proxy then
	//adds its own shared-secret header on every backend request
	//when the domain configures one. The secret is
	//config-file-only: it is never logged and never returned by
	//the API (only an ORIGIN_LOCK_CONFIGURED bool is exposed).
	request.Header.Del("X-SonuShield-Origin")
	if domainSettings.OriginLockSecret != "" {
		request.Header.Set("X-SonuShield-Origin", domainSettings.OriginLockSecret)
	}

	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-name", browser+botFp)

	//API protection gate (Batch 4): JWT validation, API-key
	//limits, and GraphQL limits. Inert unless the operator
	//configured protected paths; API clients still pass the
	//normal challenge flow above.
	if checkAPIGate(writer, request, domainName, ip, domainSettings, tlsFp, ja4Fp, httpFp, browser, botFp, domainData.Stage, susLv) {
		return
	}

	//WebSocket upgrade with an idle timeout (Batch 4). Only when
	//the operator configured websocketIdleTimeout; otherwise the
	//upgrade flows through the normal reverse proxy exactly as
	//before. Hijacking is unavailable on HTTP/2, where the normal
	//path is used instead.
	if domainSettings.WebsocketIdleTimeout > 0 && isUpgradeRequest(request) {
		if proxyWebSocket(writer, request, domainSettings) {
			return
		}
	}

	//Metering (Batch 5): request bytes from Content-Length
	//(headers excluded, chunked bodies uncounted). Response
	//bytes are counted in the RoundTripper.
	if request.ContentLength > 0 {
		addDomainBytes(domainName, request.ContentLength, 0)
	}

	//Stampede guard (Batch 6). For a cacheable GET that missed the
	//cache, collapse simultaneous identical misses into one origin
	//fetch: followers wait for the leader and then serve from the
	//cache. Inert unless the domain enables stampedeGuard with the
	//edge cache. The leader's release runs when this function
	//returns, after the fetch has populated the cache.
	if served, release := stampedeEnter(writer, request, domainSettings, domainName); served {
		return
	} else if release != nil {
		defer release()
	}

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
