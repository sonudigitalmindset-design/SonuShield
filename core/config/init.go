package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/privacy"
	"sonushield/core/proxy"
	"sonushield/core/server"
	"sonushield/core/utils"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kor44/gofilter"
)

func Load() {

	file, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			Generate()
		} else {
			panic(err)
		}
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&domains.Config)

	//Privacy mode (Batch 7): set before logging.Configure
	//runs below, so the retention cap applies from the
	//first log file onward.
	privacy.Set(domains.Config.Proxy.PrivacyMode)

	proxy.Cloudflare = domains.Config.Proxy.Cloudflare

	// Process start time for the status page (Batch 5). Set
	// once; a reload never resets it, so uptime spans the
	// whole process lifetime.
	if proxy.StartTime.IsZero() {
		proxy.StartTime = time.Now()
	}

	proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]
	if strings.Contains(proxy.CookieSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Cookie Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.JSSecret = domains.Config.Proxy.Secrets["javascript"]
	if strings.Contains(proxy.JSSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ JS Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.CaptchaSecret = domains.Config.Proxy.Secrets["captcha"]
	if strings.Contains(proxy.CaptchaSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Captcha Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.AdminSecret = domains.Config.Proxy.AdminSecret
	if strings.Contains(proxy.AdminSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Admin Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.APISecret = domains.Config.Proxy.APISecret
	if strings.Contains(proxy.APISecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ API Secret Contains 'CHANGE_ME'. Refusing To Load ]")
	}

	// Additional API secrets mapped to roles (viewer/operator/
	// admin). The main apisecret is always admin; invalid roles
	// are ignored with a warning inside SetAPIRoles.
	proxy.SetAPIRoles(domains.Config.Proxy.APIRoles)

	// SSO/OIDC (Batch 5): an enabled-but-invalid SSO config
	// disables SSO with a warning; it never stops the proxy.
	if domains.Config.Proxy.SSO != nil && domains.Config.Proxy.SSO.Enabled {
		if reason := domains.Config.Proxy.SSO.Validate(); reason != "" {
			fmt.Println("[ ! ] [ SSO disabled: " + reason + " ]")
		}
	}

	// Check if the Proxy Timeout Config has been set otherwise use default values

	if domains.Config.Proxy.Timeout.Idle != 0 {
		proxy.IdleTimeout = domains.Config.Proxy.Timeout.Idle
		proxy.IdleTimeoutDuration = time.Duration(proxy.IdleTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Read != 0 {
		proxy.ReadTimeout = domains.Config.Proxy.Timeout.Read
		proxy.ReadTimeoutDuration = time.Duration(proxy.ReadTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.ReadHeader != 0 {
		proxy.ReadHeaderTimeout = domains.Config.Proxy.Timeout.ReadHeader
		proxy.ReadHeaderTimeoutDuration = time.Duration(proxy.ReadHeaderTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Write != 0 {
		proxy.WriteTimeout = domains.Config.Proxy.Timeout.Write
		proxy.WriteTimeoutDuration = time.Duration(proxy.WriteTimeout).Abs() * time.Second
	}

	// Didn't think anyone would actually read through this mess
	if len(domains.Config.Proxy.Colors) != 0 {
		utils.SetColor(domains.Config.Proxy.Colors)
	}

	if domains.Config.Proxy.RatelimitWindow < 10 {
		domains.Config.Proxy.RatelimitWindow = 10
	}
	proxy.RatelimitWindow = domains.Config.Proxy.RatelimitWindow

	if domains.Config.Proxy.GeoIPCountryDB != "" || domains.Config.Proxy.GeoIPASNDB != "" {
		if geoErr := firewall.InitGeoIP(domains.Config.Proxy.GeoIPCountryDB, domains.Config.Proxy.GeoIPASNDB); geoErr != nil {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Failed to open GeoIP database, Geo/ASN rules will not match: " + geoErr.Error() + " ]")
		}
	}

	firewall.InitReputation(domains.Config.Proxy.ReputationList, domains.Config.Proxy.ReputationFeed, domains.Config.Proxy.ReputationIntvl, domains.Config.Proxy.ReputationSusLv)

	// Per-IP connection cap (Batch 5, slowloris guard). Disabled
	// (0) by default; see firewall/conntrack.go.
	firewall.SetMaxConnsPerIP(domains.Config.Proxy.MaxConnsPerIP)

	// Passive OS signatures (Batch 7). Empty by default; with
	// none configured every client classifies as "unknown".
	firewall.SetOSSignatures(domains.Config.Proxy.OSSignatures)

	// Structured JSON logging (Batch 2). Disabled unless logFormat
	// is "json" and logFile is set; Configure warns and disables
	// itself on any problem, so a bad log config never stops the proxy.
	logging.Configure(domains.Config.Proxy.LogFormat, domains.Config.Proxy.LogFile, domains.Config.Proxy.LogMaxBytes, domains.Config.Proxy.LogMaxFiles)

	proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.Config.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.Config.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.Config.Proxy.Ratelimits["noRequestsSent"]

	fmt.Println("Loading Fingerprints ...")

	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/bot_fingerprints.json", &firewall.BotFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/malicious_fingerprints.json", &firewall.ForbiddenFingerprints)

	//JA4 lists. Intentionally empty by default: SonuShield JA4 values are
	//only comparable with other SonuShield-computed values, so no values
	//are bundled. See global/fingerprints/SOURCES.md.
	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/ja4_known.json", &firewall.KnownJA4)
	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/ja4_bot.json", &firewall.BotJA4)
	GetFingerprints("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/fingerprints/ja4_malicious.json", &firewall.ForbiddenJA4)
	LoadJA4LocalOverrides("ja4_fingerprints.json")

	for i, domain := range domains.Config.Domains {
		domains.Domains = append(domains.Domains, domain.Name)

		if domain.ChallengeProvider != "" && ((domain.ChallengeProvider != "turnstile" && domain.ChallengeProvider != "hcaptcha") || domain.ChallengeSiteKey == "" || domain.ChallengeSecretKey == "") {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Challenge provider for " + domain.Name + " is misconfigured: need provider 'turnstile' or 'hcaptcha' plus site and secret keys. Falling back to proof-of-work challenges. ]")
		}

		firewallRules := []domains.Rule{}
		rawFirewallRules := domains.Config.Domains[i].FirewallRules
		for index, fwRule := range domains.Config.Domains[i].FirewallRules {

			rule, err := gofilter.NewFilter(fwRule.Expression)
			if err != nil {
				panic("[ " + utils.PrimaryColor("!") + " ] [ Error Loading Custom Firewall Rules For " + domain.Name + " ( Rule " + strconv.Itoa(index) + " ) : " + utils.PrimaryColor(err.Error()) + " ]")
			}

			//Scheduled rules (Batch 7): an invalid schedule
			//warns and leaves the rule always active (fail
			//safe); the API rejects invalid schedules at
			//write time, so this only triggers for
			//hand-edited configs.
			var ruleSchedule *domains.Schedule
			if strings.TrimSpace(fwRule.Schedule) != "" {
				parsed, scheduleErr := domains.ParseSchedule(fwRule.Schedule)
				if scheduleErr != nil {
					fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Invalid Schedule For Rule " + strconv.Itoa(index) + " On " + domain.Name + " : " + scheduleErr.Error() + " - rule stays always active. ]")
				} else {
					ruleSchedule = parsed
				}
			}

			firewallRules = append(firewallRules, domains.Rule{
				Filter:   rule,
				Action:   fwRule.Action,
				Schedule: ruleSchedule,
			})
		}

		//Edge rules (Batch 6): precompiled fast-path chain.
		//Rules that do not fit the fast grammar are skipped
		//with a warning; they must stay general firewall rules.
		edgeRules, edgeWarnings := firewall.CompileEdgeRules(domain.EdgeRules)
		for _, warning := range edgeWarnings {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Edge Rules For " + domain.Name + " : " + warning + " ]")
		}

		//Shadow rules (Batch 7): evaluated alongside live
		//enforcement for comparison only. Bad rules are
		//skipped with a warning, never fatal.
		shadowRules, rawShadowRules, shadowWarnings := firewall.CompileShadowRules(domain.ShadowRules)
		for _, warning := range shadowWarnings {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Shadow Rules For " + domain.Name + " : " + warning + " ]")
		}

		//Scheduled rules + maintenance windows (Batch 7):
		//both parse leniently. An invalid timezone falls
		//back to UTC with a warning; invalid windows are
		//dropped with a warning.
		scheduleLocation, tzErr := domains.ParseScheduleTimezone(domain.ScheduleTimezone)
		if tzErr != nil {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Invalid scheduleTimezone For " + domain.Name + " : " + tzErr.Error() + " - falling back to UTC. ]")
			scheduleLocation = time.UTC
		}
		maintenanceWindows, maintenanceWarnings := domains.ParseMaintenanceWindows(domain.MaintenanceWindows)
		for _, warning := range maintenanceWarnings {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Maintenance Windows For " + domain.Name + " : " + warning + " ]")
		}

		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domain.Scheme,
			Host:   domain.Backend,
		})
		dProxy.Transport = &server.RoundTripper{}
		dProxy.ModifyResponse = server.ModifyResponseHook

		// With autoSSL enabled, a domain without certificate/key paths
		// keeps the empty certificate here; domains.GetCertificate
		// falls back to the Let's Encrypt manager for such domains.
		// A domain with only one of the two paths set still fails
		// below, exactly as before.
		var cert tls.Certificate = tls.Certificate{}
		if !proxy.Cloudflare && !(domains.Config.Proxy.AutoSSL && domain.Certificate == "" && domain.Key == "") {
			var certErr error
			cert, certErr = tls.LoadX509KeyPair(domain.Certificate, domain.Key)
			if certErr != nil {
				panic("[ " + utils.PrimaryColor("!") + " ] [ " + utils.PrimaryColor("Error Loading Certificates: "+certErr.Error()) + " ]")
			}
		}

		settings := domains.DomainSettings{
			Name: domain.Name,

			CustomRules:    firewallRules,
			RawCustomRules: rawFirewallRules,
			EdgeRules:       edgeRules,
			ShadowRules:     shadowRules,
			RawShadowRules:  rawShadowRules,
			ShadowWaf:       domain.ShadowWaf,

			ScheduleLocation:   scheduleLocation,
			MaintenanceWindows: maintenanceWindows,

			DomainProxy:        dProxy,
			DomainCertificates: cert,
			DomainWebhooks: domains.WebhookSettings{
				URL:            domain.Webhook.URL,
				Name:           domain.Webhook.Name,
				Avatar:         domain.Webhook.Avatar,
				AttackStartMsg: domain.Webhook.AttackStartMsg,
				AttackStopMsg:  domain.Webhook.AttackStopMsg,
			},
			DomainTelegram: domains.TelegramSettings{
				BotToken:       domain.Telegram.BotToken,
				ChatID:         domain.Telegram.ChatID,
				AttackStartMsg: domain.Telegram.AttackStartMsg,
				AttackStopMsg:  domain.Telegram.AttackStopMsg,
			},
			DomainEmail: domains.EmailSettings{
				SMTPHost:       domain.Email.SMTPHost,
				SMTPPort:       domain.Email.SMTPPort,
				Username:       domain.Email.Username,
				Password:       domain.Email.Password,
				From:           domain.Email.From,
				To:             domain.Email.To,
				UseTLS:         domain.Email.UseTLS,
				AttackStartMsg: domain.Email.AttackStartMsg,
				AttackStopMsg:  domain.Email.AttackStopMsg,
			},
			DomainTwilio: domains.TwilioSettings{
				AccountSID:     domain.Twilio.AccountSID,
				AuthToken:      domain.Twilio.AuthToken,
				From:           domain.Twilio.From,
				To:             domain.Twilio.To,
				APIBase:        domain.Twilio.APIBase,
				AttackStartMsg: domain.Twilio.AttackStartMsg,
				AttackStopMsg:  domain.Twilio.AttackStopMsg,
			},
			Branding: domain.Branding,

			BypassStage1:        domain.BypassStage1,
			BypassStage2:        domain.BypassStage2,
			DisableBypassStage3: domain.DisableBypassStage3,
			DisableRawStage3:    domain.DisableRawStage3,
			DisableBypassStage2: domain.DisableBypassStage2,
			DisableRawStage2:    domain.DisableRawStage2,
			AdaptivePow:         domain.AdaptivePow,
			PoWDifficultyMin:    domain.PoWDifficultyMin,
			PoWDifficultyMax:    domain.PoWDifficultyMax,
			MemoryHardPow:       domain.MemoryHardPow,
			MemoryHardPowBits:   domain.MemoryHardPowBits,
			MemoryHardPowMemory: domain.MemoryHardPowMemory,
			MemoryHardPowTime:   domain.MemoryHardPowTime,
			ChallengeProvider:   domain.ChallengeProvider,
			ChallengeSiteKey:    domain.ChallengeSiteKey,
			ChallengeSecretKey:  domain.ChallengeSecretKey,
			ChallengeRotation:   domain.ChallengeRotation,
			ChallengeRotationMode: domain.ChallengeRotationMode,
			WAFMode:             domain.WAFMode,
			WAFInspectBody:      domain.WAFInspectBody,
			WAFWpLoginLimit:     domain.WAFWpLoginLimit,
			HoneypotPaths:       domain.HoneypotPaths,
			HoneypotSusLv:       domain.HoneypotSusLv,
			CanaryPaths:         domain.CanaryPaths,
			CanaryTokens:        domain.CanaryTokens,
			SignedURLSecret:     domain.SignedURLSecret,
			SignedURLPaths:      domain.SignedURLPaths,
			HotlinkProtect:      domain.HotlinkProtect,
			HotlinkPaths:        domain.HotlinkPaths,
			HotlinkAllowlist:    domain.HotlinkAllowlist,
			FormGuard:           domain.FormGuard,
			SLATarget:           domain.SLATarget,
			FakeBotCheck:        domain.FakeBotCheck,
			FakeBotSusLv:        domain.FakeBotSusLv,
			TarpitDelayMs:       domain.TarpitDelayMs,
			TarpitSusLv:         domain.TarpitSusLv,
			TarpitMaxConns:      domain.TarpitMaxConns,
			EdgeCache:           domain.EdgeCache,
			EdgeCacheTTL:        domain.EdgeCacheTTL,
			EdgeCacheMaxMB:      domain.EdgeCacheMaxMB,
			Brotli:              domain.Brotli,
			ImageOptimize:       domain.ImageOptimize,
			ImageOptimizeMaxWidth: domain.ImageOptimizeMaxWidth,
			ImageOptimizeQuality: domain.ImageOptimizeQuality,
			StampedeGuard:       domain.StampedeGuard,
			WaitingRoom:         domain.WaitingRoom,
			WaitingRoomThreshold: domain.WaitingRoomThreshold,
			WaitingRoomAdmit:    domain.WaitingRoomAdmit,
			Backends:            domain.Backends,
			LBPolicy:            domain.LBPolicy,
			HealthCheckEnabled:  domain.HealthCheckEnabled,
			HealthCheckPath:     domain.HealthCheckPath,
			HealthCheckInterval: domain.HealthCheckInterval,
			PoolMaxIdleConns:    domain.PoolMaxIdleConns,
			PoolMaxIdleConnsPerHost: domain.PoolMaxIdleConnsPerHost,
			PoolMaxConnsPerHost: domain.PoolMaxConnsPerHost,
			PoolIdleConnTimeout: domain.PoolIdleConnTimeout,
			WebsocketIdleTimeout: domain.WebsocketIdleTimeout,
			JWTProtectedPaths:   domain.JWTProtectedPaths,
			APIKeyHeader:        domain.APIKeyHeader,
			APIKeyPaths:         domain.APIKeyPaths,
			GraphQLPath:         domain.GraphQLPath,
			Passkey:             domain.Passkey,
			GraphQLMaxDepth:     domain.GraphQLMaxDepth,
			GraphQLMaxFields:    domain.GraphQLMaxFields,
			RulesDryRun:         domain.RulesDryRun,
			RiskHighRiskCountries: domain.RiskHighRiskCountries,
			RiskHighRiskASNs:    domain.RiskHighRiskASNs,
			ShareReputation:     domain.ShareReputation,
			SharedReputationSusLv: domain.SharedReputationSusLv,
			TimingEnforce:         domain.TimingEnforce,
			TimingSusLv:           domain.TimingSusLv,
			BehaviorCheck:         domain.BehaviorCheck,
			BehaviorEnforce:       domain.BehaviorEnforce,
			BehaviorSusLv:         domain.BehaviorSusLv,
			InvisibleMarkers:      domain.InvisibleMarkers,
			SessionRatelimit:      domain.SessionRatelimit,
			MaxBodyBytes:          domain.MaxBodyBytes,
			BodyLimits:            domain.BodyLimits,
			OriginLockSecret:      domain.OriginLockSecret,
			SecurityHeaders:     domain.SecurityHeaders,
			CORS:                domain.CORS,
			IPAllowlist:         domain.IPAllowlist,
			IPBlocklist:         domain.IPBlocklist,
			PageTemplates:       domain.PageTemplates,
			Tenant:              domains.NormalizeTenant(domain.Tenant),
		}
		domains.InitRuntime(&settings, domain)
		domains.DomainsMap.Store(domain.Name, settings)

		firewall.Mutex.Lock()

		if domain.Stage2Difficulty == 0 {
			domain.Stage2Difficulty = 5
		}

		domains.DomainsData[domain.Name] = domains.DomainData{
			Name:             domain.Name,
			Stage:            1,
			StageManuallySet: false,
			Stage2Difficulty: domain.Stage2Difficulty,
			RawAttack:        false,
			BypassAttack:     false,
			LastLogs:         []domains.DomainLog{},

			TotalRequests:    0,
			BypassedRequests: 0,

			PrevRequests: 0,
			PrevBypassed: 0,

			RequestsPerSecond:             0,
			RequestsBypassedPerSecond:     0,
			PeakRequestsPerSecond:         0,
			PeakRequestsBypassedPerSecond: 0,
			RequestLogger:                 []domains.RequestLog{},
		}
		firewall.Mutex.Unlock()
	}

	// Cross-domain reputation sharing (Batch 5): enabled proxy-wide
	// when at least one domain opted in. Recording and lookup are
	// both skipped when no domain opted in.
	sharedRepEnabled := false
	for _, domain := range domains.Config.Domains {
		if domain.ShareReputation {
			sharedRepEnabled = true
			break
		}
	}
	firewall.SetSharedReputationEnabled(sharedRepEnabled)

	// Backend health checks (Batch 4): one background loop for all
	// domains. Pools without health checks enabled are skipped.
	domains.StartHealthChecks()

	// Auto SSL: build the Let's Encrypt manager from the final domain
	// list. Disabled by default; in Cloudflare mode there is no TLS
	// listener, so the option is ignored with a warning.
	if domains.Config.Proxy.AutoSSL && proxy.Cloudflare {
		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ autoSSL is enabled but Cloudflare mode has no TLS listener; automatic certificates are disabled. ]")
	}
	domains.ConfigureAutoCert()

	domains.DomainsMap.Store("debug", domains.DomainSettings{
		Name: "debug",
	})

	firewall.Mutex.Lock()
	domains.DomainsData["debug"] = domains.DomainData{
		Name:             "debug",
		Stage:            0,
		StageManuallySet: false,
		RawAttack:        false,
		BypassAttack:     false,
		BufferCooldown:   0,
		LastLogs:         []domains.DomainLog{},

		TotalRequests:    0,
		BypassedRequests: 0,

		PrevRequests: 0,
		PrevBypassed: 0,

		RequestsPerSecond:             0,
		RequestsBypassedPerSecond:     0,
		PeakRequestsPerSecond:         0,
		PeakRequestsBypassedPerSecond: 0,
		RequestLogger:                 []domains.RequestLog{},
	}

	firewall.Mutex.Unlock()

	vcErr := VersionCheck()
	if vcErr != nil {
		panic("[ " + utils.PrimaryColor("!") + " ] [ " + vcErr.Error() + " ]")
	}

	if len(domains.Domains) == 0 {
		AddDomain()
		Load()
	} else {
		proxy.WatchedDomain = domains.Domains[0]
	}
}

func VersionCheck() error {
	resp, err := http.Get("https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/global/proxy/version.json")
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}

	var proxyVersions GLOBAL_PROXY_VERSIONS
	err = json.Unmarshal(body, &proxyVersions)
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}

	if proxyVersions.StableVersion > proxy.ProxyVersion {

		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ New Proxy Version " + fmt.Sprint(proxyVersions.StableVersion) + " Found. You Are using " + fmt.Sprint(proxy.ProxyVersion) + ". Consider Downloading The New Version From Github Or " + proxyVersions.Download + " ]")
		fmt.Println("[ " + utils.PrimaryColor("+") + " ] [ Automatically Starting Proxy In 10 Seconds ]")

		time.Sleep(10 * time.Second)

	}

	return nil
}
