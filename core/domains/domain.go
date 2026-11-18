package domains

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/kor44/gofilter"
)

var (
	Domains     = []string{}
	DomainsMap  sync.Map
	DomainsData = map[string]DomainData{}
	Config      *Configuration
)

type Configuration struct {
	Proxy   Proxy    `json:"proxy"`
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name                string           `json:"name"`
	Backend             string           `json:"backend"`
	Scheme              string           `json:"scheme"`
	Certificate         string           `json:"certificate"`
	Key                 string           `json:"key"`
	Webhook             WebhookSettings  `json:"webhook"`
	Telegram            TelegramSettings `json:"telegram"`
	Email               EmailSettings    `json:"email"`
	Twilio              TwilioSettings   `json:"twilio"`
	Branding            Branding         `json:"branding"`
	FirewallRules       []JsonRule       `json:"firewallRules"`
	EdgeRules           []JsonRule       `json:"edgeRules"`
	ShadowRules         []JsonRule       `json:"shadowRules"`
	ShadowWaf           bool             `json:"shadowWaf"`
	BypassStage1        int              `json:"bypassStage1"`
	BypassStage2        int              `json:"bypassStage2"`
	Stage2Difficulty    int              `json:"stage2Difficulty"`
	AdaptivePow         bool             `json:"adaptivePow"`
	PoWDifficultyMin    int              `json:"powDifficultyMin"`
	PoWDifficultyMax    int              `json:"powDifficultyMax"`
	MemoryHardPow       bool             `json:"memoryHardPow"`
	MemoryHardPowBits   int              `json:"memoryHardPowBits"`
	MemoryHardPowMemory int              `json:"memoryHardPowMemoryKB"`
	MemoryHardPowTime   int              `json:"memoryHardPowTime"`
	ChallengeProvider   string           `json:"challengeProvider"`
	ChallengeSiteKey    string           `json:"challengeSiteKey"`
	ChallengeSecretKey  string           `json:"challengeSecretKey"`
	ChallengeRotation   []string         `json:"challengeRotation"`
	ChallengeRotationMode string         `json:"challengeRotationMode"`
	WAFMode             string           `json:"wafMode"`
	HoneypotPaths       []string         `json:"honeypotPaths"`
	HoneypotSusLv       int              `json:"honeypotSusLv"`
	CanaryPaths         []string         `json:"canaryPaths"`
	CanaryTokens        []string         `json:"canaryTokens"`
	SignedURLSecret     string           `json:"signedURLSecret"`
	SignedURLPaths      []string         `json:"signedURLPaths"`
	HotlinkProtect      bool             `json:"hotlinkProtect"`
	HotlinkPaths        []string         `json:"hotlinkPaths"`
	HotlinkAllowlist    []string         `json:"hotlinkAllowlist"`
	FormGuard           FormGuardConfig  `json:"formGuard"`
	CredentialStuffing  StuffingConfig   `json:"credentialStuffing"`
	SessionHijack       SessionHijackConfig `json:"sessionHijack"`
	SLATarget           float64          `json:"slaTarget"`
	FakeBotCheck        bool             `json:"fakeBotCheck"`
	FakeBotSusLv        int              `json:"fakeBotSusLv"`
	TarpitDelayMs       int              `json:"tarpitDelayMs"`
	TarpitSusLv         int              `json:"tarpitSusLv"`
	TarpitMaxConns      int              `json:"tarpitMaxConns"`
	FairQueue           bool             `json:"fairQueue"`
	FairQueueMaxInflight int             `json:"fairQueueMaxInflight"`
	FairQueueWaitMs     int              `json:"fairQueueWaitMs"`
	EdgeCache           bool             `json:"edgeCache"`
	EdgeCacheTTL        int              `json:"edgeCacheTTL"`
	EdgeCacheMaxMB      int              `json:"edgeCacheMaxMB"`
	Brotli              bool             `json:"brotli"`
	ImageOptimize       bool             `json:"imageOptimize"`
	ImageOptimizeMaxWidth int             `json:"imageOptimizeMaxWidth"`
	ImageOptimizeQuality int             `json:"imageOptimizeQuality"`
	StampedeGuard       bool             `json:"stampedeGuard"`
	WaitingRoom         bool             `json:"waitingRoom"`
	WaitingRoomThreshold int              `json:"waitingRoomThreshold"`
	WaitingRoomAdmit    int              `json:"waitingRoomAdmit"`
	Backends            []string         `json:"backends"`
	LBPolicy            string           `json:"lbPolicy"`
	HealthCheckEnabled  bool             `json:"healthCheckEnabled"`
	HealthCheckPath     string           `json:"healthCheckPath"`
	HealthCheckInterval int              `json:"healthCheckInterval"`
	PoolMaxIdleConns    int              `json:"poolMaxIdleConns"`
	PoolMaxIdleConnsPerHost int           `json:"poolMaxIdleConnsPerHost"`
	PoolMaxConnsPerHost int              `json:"poolMaxConnsPerHost"`
	PoolIdleConnTimeout int              `json:"poolIdleConnTimeout"`
	WebsocketIdleTimeout int             `json:"websocketIdleTimeout"`
	JWTSecret           string           `json:"jwtSecret"`
	JWTJWKSURL          string           `json:"jwtJWKSURL"`
	JWTProtectedPaths   []string         `json:"jwtProtectedPaths"`
	APIKeys             []APIKeyConfig   `json:"apiKeys"`
	APIKeyHeader        string           `json:"apiKeyHeader"`
	APIKeyPaths         []string         `json:"apiKeyPaths"`
	GraphQLPath         string           `json:"graphqlPath"`
	Attestation         AttestationConfig `json:"attestation"`
	Passkey             PasskeyConfig     `json:"passkey"`
	GraphQLMaxDepth     int              `json:"graphqlMaxDepth"`
	GraphQLMaxFields    int              `json:"graphqlMaxFields"`
	RulesDryRun         bool             `json:"rulesDryRun"`
	RiskHighRiskCountries []string       `json:"riskHighRiskCountries"`
	RiskHighRiskASNs    []int            `json:"riskHighRiskASNs"`
	ShareReputation     bool             `json:"shareReputation"`
	SharedReputationSusLv int            `json:"sharedReputationSusLv"`
	TimingEnforce       bool             `json:"timingEnforce"`
	TimingSusLv         int              `json:"timingSusLv"`
	BehaviorCheck       bool             `json:"behaviorCheck"`
	BehaviorEnforce     bool             `json:"behaviorEnforce"`
	BehaviorSusLv       int              `json:"behaviorSusLv"`
	InvisibleMarkers    bool             `json:"invisibleMarkers"`
	SessionRatelimit    int              `json:"sessionRatelimit"`
	MaxBodyBytes        int64           `json:"maxBodyBytes"`
	BodyLimits          []BodyLimit     `json:"bodyLimits"`
	OriginLockSecret    string          `json:"originLockSecret"`
	SecurityHeaders     map[string]string `json:"securityHeaders"`
	CORS                *CORSConfig     `json:"cors"`
	IPAllowlist         []IPListEntry   `json:"ipAllowlist"`
	IPBlocklist         []IPListEntry   `json:"ipBlocklist"`
	PageTemplates       *PageTemplates  `json:"pageTemplates"`
	Tenant              string          `json:"tenant"`
	WAFInspectBody      bool             `json:"wafInspectBody"`
	WAFWpLoginLimit     int              `json:"wafWpLoginLimit"`
	DisableBypassStage3 int              `json:"disableBypassStage3"`
	DisableRawStage3    int              `json:"disableRawStage3"`
	DisableBypassStage2 int              `json:"disableBypassStage2"`
	DisableRawStage2    int              `json:"disableRawStage2"`
	// Scheduled rules + maintenance windows (Batch 7).
	// ScheduleTimezone is an IANA name (default UTC; invalid
	// falls back to UTC with a warning). MaintenanceWindows
	// are scheduled maintenance periods; see
	// MaintenanceWindow.
	ScheduleTimezone  string              `json:"scheduleTimezone"`
	MaintenanceWindows []MaintenanceWindow `json:"maintenanceWindows"`
	// Cloudflare import (Batch 7). Config-only credentials:
	// the token is never accepted via the API, never logged,
	// and never returned by any API action; both config
	// redactors cover it. APIBase defaults to the public
	// Cloudflare API and exists so the import can be tested
	// against a mock server.
	CloudflareAPIToken string `json:"cloudflareApiToken"`
	CloudflareZoneID   string `json:"cloudflareZoneId"`
	CloudflareAPIBase  string `json:"cloudflareApiBase"`
}

type DomainSettings struct {
	Name string

	CustomRules    []Rule
	RawCustomRules []JsonRule
	EdgeRules      []EdgeRule
	ShadowRules    []Rule
	// ScheduleLocation is the parsed scheduleTimezone (UTC
	// when unset or invalid). MaintenanceWindows holds the
	// parsed scheduled windows; invalid windows are dropped
	// with a warning at load time.
	ScheduleLocation   *time.Location
	MaintenanceWindows []ParsedMaintenanceWindow
	RawShadowRules []JsonRule
	ShadowWaf      bool

	DomainProxy        *httputil.ReverseProxy
	DomainCertificates tls.Certificate
	DomainWebhooks     WebhookSettings
	DomainTelegram     TelegramSettings
	DomainEmail        EmailSettings
	DomainTwilio       TwilioSettings
	Branding           Branding

	BypassStage1        int
	BypassStage2        int
	DisableBypassStage3 int
	DisableRawStage3    int
	DisableBypassStage2 int
	DisableRawStage2    int
	AdaptivePow         bool
	PoWDifficultyMin    int
	PoWDifficultyMax    int
	MemoryHardPow       bool
	MemoryHardPowBits   int
	MemoryHardPowMemory int
	MemoryHardPowTime   int
	ChallengeProvider   string
	ChallengeSiteKey    string
	ChallengeSecretKey  string
	ChallengeRotation   []string
	ChallengeRotationMode string
	WAFMode             string
	WAFInspectBody      bool
	WAFWpLoginLimit     int
	HoneypotPaths       []string
	HoneypotSusLv       int
	CanaryPaths         []string
	CanaryTokens        []string
	SignedURLSecret     string
	SignedURLPaths      []string
	HotlinkProtect      bool
	HotlinkPaths        []string
	HotlinkAllowlist    []string
	FormGuard           FormGuardConfig
	CredentialStuffing  StuffingConfig
	SessionHijack       SessionHijackConfig
	SLATarget           float64
	FakeBotCheck        bool
	FakeBotSusLv        int
	TarpitDelayMs       int
	TarpitSusLv         int
	TarpitMaxConns      int
	EdgeCache           bool
	EdgeCacheTTL        int
	EdgeCacheMaxMB      int
	Brotli              bool
	ImageOptimize       bool
	ImageOptimizeMaxWidth int
	ImageOptimizeQuality int
	StampedeGuard       bool
	WaitingRoom         bool
	WaitingRoomThreshold int
	WaitingRoomAdmit    int
	Backends            []string
	LBPolicy            string
	HealthCheckEnabled  bool
	HealthCheckPath     string
	HealthCheckInterval int
	PoolMaxIdleConns    int
	PoolMaxIdleConnsPerHost int
	PoolMaxConnsPerHost int
	PoolIdleConnTimeout int
	WebsocketIdleTimeout int
	JWTProtectedPaths   []string
	APIKeyHeader        string
	APIKeyPaths         []string
	GraphQLPath         string
	GraphQLMaxDepth     int
	GraphQLMaxFields    int
	RulesDryRun         bool
	RiskHighRiskCountries []string
	RiskHighRiskASNs      []int
	ShareReputation       bool
	SharedReputationSusLv int
	TimingEnforce         bool
	TimingSusLv           int
	BehaviorCheck         bool
	BehaviorEnforce       bool
	BehaviorSusLv         int
	InvisibleMarkers      bool
	SessionRatelimit      int
	MaxBodyBytes          int64
	BodyLimits            []BodyLimit
	OriginLockSecret      string
	SecurityHeaders     map[string]string
	CORS                *CORSConfig
	IPAllowlist         []IPListEntry
	IPBlocklist         []IPListEntry
	IPAllowCompiled     []compiledIPEntry
	IPBlockCompiled     []compiledIPEntry
	PageTemplates       *PageTemplates
	Tenant              string

	//Runtime state, built by InitRuntime. Nil when the feature is
	//disabled; every object is safe to use through a nil pointer.
	Tarpit  *TarpitLimiter
	Cache   *EdgeCache
	Waiting *WaitingRoom
	FairQueue *FairQueue
	Pool    *BackendPool
	JWT     *JWTVerifier
	APIKeys *APIKeyState
	Attest  *AttestationVerifier
	Passkey  PasskeyConfig
	Passkeys *PasskeyStore
}

type DomainLog struct {
	Time      string
	IP        string
	BrowserFP string
	BotFP     string
	TLSFP     string
	Useragent string
	Path      string
}

type DomainData struct {
	Name             string
	Stage            int
	StageManuallySet bool
	Stage2Difficulty int
	RawAttack        bool
	BypassAttack     bool
	BufferCooldown   int

	LastLogs []DomainLog

	TotalRequests    int
	BypassedRequests int

	PrevRequests int
	PrevBypassed int

	RequestsPerSecond             int
	RequestsBypassedPerSecond     int
	PeakRequestsPerSecond         int
	PeakRequestsBypassedPerSecond int
	RequestLogger                 []RequestLog

	// Risk-score aggregates (Batch 5): every evaluated request
	// contributes its composite score, so attack reports can
	// summarise average and peak risk. Reset by reload, like the
	// other counters.
	RiskSum   int64
	RiskCount int64
	RiskMax   int

	// Bandwidth estimate (Batch 5): request bytes from
	// Content-Length and response bytes counted as bodies are
	// read, for proxied and cache-served traffic only. Challenge
	// pages, block pages, and WebSocket traffic are not counted.
	// Reset by reload, like the other counters.
	BytesIn  int64
	BytesOut int64
}

type Proxy struct {
	Cloudflare      bool              `json:"cloudflare"`
	AdminSecret     string            `json:"adminsecret"`
	APISecret       string            `json:"apisecret"`
	APIRoles        map[string]string `json:"apiRoles"`
	Secrets         map[string]string `json:"secrets"`
	Timeout         TimeoutSettings   `json:"timeout"`
	RatelimitWindow int               `json:"ratelimit_time"`
	GeoIPCountryDB  string            `json:"geoipCountryDatabase"`
	GeoIPASNDB      string            `json:"geoipASNDatabase"`
	ReputationList  []string          `json:"reputationBlocklist"`
	ReputationFeed  string            `json:"reputationFeedURL"`
	ReputationIntvl int               `json:"reputationFeedInterval"`
	ReputationSusLv int               `json:"reputationSusLv"`
	AutoSSL         bool              `json:"autoSSL"`
	AutoSSLCacheDir string            `json:"autoSSLCacheDir"`
	AutoSSLEmail    string            `json:"autoSSLEmail"`
	QuietMode       bool              `json:"quietMode"`
	Branding        Branding          `json:"branding"`
	TLSDisablePostQuantum bool      `json:"tlsDisablePostQuantum"`
	OSSignatures          []OSSignature `json:"osSignatures,omitempty"`
	MetricsEnabled  bool              `json:"metricsEnabled"`
	ReportDirectory string            `json:"reportDirectory"`
	LogFormat       string            `json:"logFormat"`
	LogFile         string            `json:"logFile"`
	LogMaxBytes     int64             `json:"logMaxBytes"`
	LogMaxFiles     int               `json:"logMaxFiles"`
	ConfigBackups   int               `json:"configBackups"`
	MaxConnsPerIP   int               `json:"maxConnsPerIP"`
	MaxRequestBody  int64            `json:"maxRequestBody"`
	StatusPage      bool             `json:"statusPage"`
	GitOps          GitOpsConfig     `json:"gitops"`
	SSO             *SSOConfig      `json:"sso"`
	Stripe          StripeConfig    `json:"stripe"`
	PublicAPIKeys   []PublicAPIKey  `json:"publicApiKeys"`
	EventWebhooks   []EventWebhookConfig `json:"eventWebhooks"`
	Ratelimits      map[string]int    `json:"ratelimits"`
	Colors          []string          `json:"colors"`
	// Certificate + subdomain alerts (Batch 7). CertAlerts
	// enables hourly expiry checks; CertAlertDays is the
	// warning threshold (<= 0 means 14). SubdomainMonitor
	// watches operator-supplied names via DNS; nil or
	// disabled means no monitoring.
	CertAlerts       bool                    `json:"certAlerts"`
	CertAlertDays    int                     `json:"certAlertDays"`
	SubdomainMonitor *SubdomainMonitorConfig `json:"subdomainMonitor"`
	// Privacy mode (Batch 7). When true, IPs are
	// anonymized and user-agents dropped in stored logs,
	// reports, and API responses, and log retention is
	// capped at 2 files. Off by default.
	PrivacyMode bool `json:"privacyMode"`
	// Two-person approval (Batch 7). When true, sensitive
	// control actions need a second distinct approver
	// before executing. ApprovalExpirySeconds is the
	// pending-approval lifetime (<= 0 means 300). Off by
	// default; single-operator setups are unaffected.
	TwoPersonApproval   bool `json:"twoPersonApproval"`
	ApprovalExpirySeconds int `json:"approvalExpirySeconds"`
}

// SubdomainMonitorConfig watches operator-supplied domain
// names by resolving them periodically. IntervalMinutes
// defaults to 60 and is clamped to a minimum of 5.
// FailureThreshold defaults to 3 and is clamped to a
// minimum of 1: that many consecutive resolution failures
// trigger one alert.
type SubdomainMonitorConfig struct {
	Enabled          bool     `json:"enabled"`
	Domains          []string `json:"domains"`
	IntervalMinutes  int      `json:"intervalMinutes"`
	FailureThreshold int      `json:"failureThreshold"`
}

type TimeoutSettings struct {
	Idle       int `json:"idle"`
	Read       int `json:"read"`
	Write      int `json:"write"`
	ReadHeader int `json:"read_header"`
}

type WebhookSettings struct {
	URL            string `json:"url"`
	Name           string `json:"name"`
	Avatar         string `json:"avatar"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type TelegramSettings struct {
	BotToken       string `json:"botToken"`
	ChatID         string `json:"chatId"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type EmailSettings struct {
	SMTPHost       string `json:"smtpHost"`
	SMTPPort       int    `json:"smtpPort"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	From           string `json:"from"`
	To             string `json:"to"`
	UseTLS         bool   `json:"useTLS"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

// TwilioSettings holds the operator's own Twilio (or
// Twilio-compatible) account for WhatsApp/SMS alerts. From/To
// values prefixed with "whatsapp:" go via WhatsApp, plain E.164
// numbers via SMS. APIBase overrides the default
// https://api.twilio.com for compatible providers; empty means
// the default. All of AccountSID, AuthToken, From, and To are
// required; the channel is inert when any is missing.
// Branding is the operator-configured display identity for the
// dashboard and the built-in challenge pages. See branding.go
// for the safety rules and the GPL-attribution hard limit.
type Branding struct {
	DisplayName string `json:"displayName"`
	LogoURL     string `json:"logoURL"`
	AccentColor string `json:"accentColor"`
}

type TwilioSettings struct {
	AccountSID     string `json:"accountSID"`
	AuthToken      string `json:"authToken"`
	From           string `json:"from"`
	To             string `json:"to"`
	APIBase        string `json:"apiBase"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type JsonRule struct {
	Expression string `json:"expression"`
	Action     string `json:"action"`
	// Schedule is an optional 5-field cron expression; the
	// rule only applies when the schedule matches in the
	// domain's scheduleTimezone. Empty means always active.
	// Schedules apply to general rules only; edge rules
	// ignore them.
	Schedule string `json:"schedule,omitempty"`
}

// MaintenanceWindow is one scheduled maintenance period in
// the domain configuration. Start and End are RFC 3339
// timestamps; Message is shown on the maintenance page
// (empty uses the default text).
type MaintenanceWindow struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Message string `json:"message,omitempty"`
}

// ParsedMaintenanceWindow is a validated maintenance
// window held in the runtime settings.
type ParsedMaintenanceWindow struct {
	Start   time.Time
	End     time.Time
	Message string
}

// FormGuardConfig is the per-domain form spam guard
// configuration (Batch 7, domain.formGuard). Paths lists the
// guarded path prefixes; HoneypotField names the hidden field
// the operator added to their forms (default "website");
// MinSeconds is the minimum sane form-fill time (default 3);
// MaxPerMinute is the per-IP per-path POST limit (default
// 30); Mode is "log" (default, log only) or "block".
type FormGuardConfig struct {
	Paths        []string `json:"paths"`
	HoneypotField string  `json:"honeypotField"`
	MinSeconds   int     `json:"minSeconds"`
	MaxPerMinute int     `json:"maxPerMinute"`
	Mode         string  `json:"mode"`
}

// OSSignature is one operator-supplied passive OS signature
// (Batch 7, proxy.osSignatures). A client matches when every
// specified field matches the observed TCP_INFO signals:
// a zero MSS means "any", a nil option pointer means "any".
// The label is operator-chosen free text; SonuShield ships no
// signature table of its own.
type OSSignature struct {
	Label      string `json:"label"`
	SndMSS     int    `json:"sndMss,omitempty"`
	RcvMSS     int    `json:"rcvMss,omitempty"`
	WScale     *bool  `json:"wscale,omitempty"`
	Timestamps *bool  `json:"timestamps,omitempty"`
	SACK       *bool  `json:"sack,omitempty"`
}

type Rule struct {
	Filter *gofilter.Filter
	Action string
	// Schedule is the parsed cron schedule, or nil when the
	// rule has none (or its schedule was invalid at load
	// time, in which case the rule stays always active).
	Schedule *Schedule
}

type RequestLog struct {
	Time     time.Time
	Allowed  int
	Total    int
	CpuUsage string
}

type CacheResponse struct {
	Domain    string
	Timestamp int
	Status    int
	Headers   http.Header
	Body      []byte
}
