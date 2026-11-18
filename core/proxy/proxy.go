package proxy

import "time"

const (
	ProxyVersion float64 = 1.5
)

var (
	Fingerprint string

	WatchedDomain string
	TWidth        int
	THeight       int
	Cloudflare    bool
	MaxLogLength  int

	CpuUsage string
	RamUsage string

	AdminSecret string
	APISecret   string

	// ControlPlaneSecret is the shared secret under which a
	// trusted control plane proves caller identities for
	// two-person approval. Empty disables the mechanism.
	ControlPlaneSecret string

	// DashboardMode controls the on-domain dashboard:
	// "local" (default) serves it as before, "control-plane"
	// redirects dashboard requests to ControlPlaneURL (or
	// answers a bare 404 without one), and "off" disables
	// the path entirely. Unknown values fail safe to "off".
	DashboardMode string

	// ControlPlaneURL is the control-plane dashboard URL
	// that on-domain dashboard requests redirect to when
	// DashboardMode is "control-plane". It must be an
	// absolute http(s) URL; anything else falls back to a
	// bare 404 at request time.
	ControlPlaneURL string

	CookieSecret string
	CookieOTP    string

	JSSecret string
	JSOTP    string

	JSDifficulty = 5

	CaptchaSecret string
	CaptchaOTP    string

	IdleTimeout       = 5
	ReadTimeout       = 5
	WriteTimeout      = 7
	ReadHeaderTimeout = 5

	IdleTimeoutDuration       = time.Duration(IdleTimeout).Abs() * time.Second
	ReadTimeoutDuration       = time.Duration(ReadTimeout).Abs() * time.Second
	WriteTimeoutDuration      = time.Duration(WriteTimeout).Abs() * time.Second
	ReadHeaderTimeoutDuration = time.Duration(ReadHeaderTimeout).Abs() * time.Second

	RatelimitWindow = 120

	IPRatelimit            int
	FPRatelimit            int
	FailChallengeRatelimit int
	FailRequestRatelimit   int

	CurrHour               int
	CurrHourStr            string
	LastSecondTime         time.Time
	LastSecondTimeFormated string
	LastSecondTimestamp    int
	Last10SecondTimestamp  int

	Initialised = false

	// StartTime is when the process started, set once by
	// config.Load. It is never reset by a reload, so the status
	// page uptime spans the whole process lifetime.
	StartTime time.Time
)
