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
	FirewallRules       []JsonRule       `json:"firewallRules"`
	BypassStage1        int              `json:"bypassStage1"`
	BypassStage2        int              `json:"bypassStage2"`
	Stage2Difficulty    int              `json:"stage2Difficulty"`
	AdaptivePow         bool             `json:"adaptivePow"`
	PoWDifficultyMin    int              `json:"powDifficultyMin"`
	PoWDifficultyMax    int              `json:"powDifficultyMax"`
	ChallengeProvider   string           `json:"challengeProvider"`
	ChallengeSiteKey    string           `json:"challengeSiteKey"`
	ChallengeSecretKey  string           `json:"challengeSecretKey"`
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
	WaitingRoom         bool             `json:"waitingRoom"`
	WaitingRoomThreshold int              `json:"waitingRoomThreshold"`
	WaitingRoomAdmit    int              `json:"waitingRoomAdmit"`
	Backends            []string         `json:"backends"`
	LBPolicy            string           `json:"lbPolicy"`
	HealthCheckEnabled  bool             `json:"healthCheckEnabled"`
	HealthCheckPath     string           `json:"healthCheckPath"`
	HealthCheckInterval int              `json:"healthCheckInterval"`
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

	DomainProxy        *httputil.ReverseProxy
	DomainCertificates tls.Certificate
	DomainWebhooks     WebhookSettings
	DomainTelegram     TelegramSettings
	DomainEmail        EmailSettings

	BypassStage1        int
	BypassStage2        int
	DisableBypassStage3 int
	DisableRawStage3    int
	DisableBypassStage2 int
	DisableRawStage2    int
	AdaptivePow         bool
	PoWDifficultyMin    int
	PoWDifficultyMax    int
	ChallengeProvider   string
	ChallengeSiteKey    string
	ChallengeSecretKey  string
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
	WaitingRoom         bool
	WaitingRoomThreshold int
	WaitingRoomAdmit    int
	Backends            []string
	LBPolicy            string
	HealthCheckEnabled  bool
	HealthCheckPath     string
	HealthCheckInterval int
	WebsocketIdleTimeout int
	JWTProtectedPaths   []string
	APIKeyHeader        string
	APIKeyPaths         []string
	GraphQLPath         string
	GraphQLMaxDepth     int
	GraphQLMaxFields    int

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
	MetricsEnabled  bool              `json:"metricsEnabled"`
	ReportDirectory string            `json:"reportDirectory"`
	LogFormat       string            `json:"logFormat"`
	LogFile         string            `json:"logFile"`
	LogMaxBytes     int64             `json:"logMaxBytes"`
	LogMaxFiles     int               `json:"logMaxFiles"`
	ConfigBackups   int               `json:"configBackups"`
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
