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
	FakeBotCheck        bool             `json:"fakeBotCheck"`
	FakeBotSusLv        int              `json:"fakeBotSusLv"`
	TarpitDelayMs       int              `json:"tarpitDelayMs"`
	TarpitSusLv         int              `json:"tarpitSusLv"`
	TarpitMaxConns      int              `json:"tarpitMaxConns"`
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
	GraphQLMaxDepth     int              `json:"graphqlMaxDepth"`
	GraphQLMaxFields    int              `json:"graphqlMaxFields"`
	RulesDryRun         bool             `json:"rulesDryRun"`
	RiskHighRiskCountries []string       `json:"riskHighRiskCountries"`
	RiskHighRiskASNs    []int            `json:"riskHighRiskASNs"`
	ShareReputation     bool             `json:"shareReputation"`
	SharedReputationSusLv int            `json:"sharedReputationSusLv"`
	TimingEnforce       bool             `json:"timingEnforce"`
	TimingSusLv         int              `json:"timingSusLv"`
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
}

type DomainSettings struct {
	Name string

	CustomRules    []Rule
	RawCustomRules []JsonRule
	EdgeRules      []EdgeRule

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
	Pool    *BackendPool
	JWT     *JWTVerifier
	APIKeys *APIKeyState
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
	Ratelimits      map[string]int    `json:"ratelimits"`
	Colors          []string          `json:"colors"`
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
}

type Rule struct {
	Filter *gofilter.Filter
	Action string
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
