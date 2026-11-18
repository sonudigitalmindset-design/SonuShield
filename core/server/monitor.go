package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inancgumus/screen"
	"github.com/kor44/gofilter"
	"github.com/shirou/gopsutil/v4/cpu"
	"golang.org/x/term"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/oncalls"
	"sonushield/core/pnc"
	"sonushield/core/privacy"
	"sonushield/core/proxy"
	"sonushield/core/reports"
	"sonushield/core/sharing"
	"sonushield/core/timeline"
	"sonushield/core/utils"
)

var (
	PrintMutex = &sync.Mutex{}
	helpMode   = false
)

func Monitor() {

	defer pnc.PanicHndl()

	PrintMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
	PrintMutex.Unlock()

	proxy.LastSecondTime = time.Now()
	proxy.LastSecondTimeFormated = proxy.LastSecondTime.Format("15:04:05")
	proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix())
	proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()
	proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)

	//Responsible for handeling user-commands
	go commands()

	//Responsible for clearing outdated cache and data
	go clearProxyCache()

	//Responsible for generating non-bruteforable secrets
	go generateOTPSecrets()

	//Responsible for keeping track of ratelimit
	go evaluateRatelimit()

	PrintMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(11+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
	PrintMutex.Unlock()
	for {
		PrintMutex.Lock()
		tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
		proxy.TWidth = tempWidth + 18
		if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {
			proxy.THeight = tempHeight

			pHeight := tempHeight - 15
			if pHeight < 0 {
				proxy.MaxLogLength = 0
			} else {
				proxy.MaxLogLength = pHeight
			}

			screen.Clear()
			screen.MoveTopLeft()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")

		firewall.Mutex.Lock()
		for name, data := range domains.DomainsData {
			checkAttack(name, data)
		}
		firewall.Mutex.Unlock()

		printStats()

		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

// Only run this inside of a locked thread to avoid false reports
func checkAttack(domainName string, domainData domains.DomainData) {

	if domainName == "debug" {
		return
	}

	domainData.RequestsPerSecond = domainData.TotalRequests - domainData.PrevRequests
	domainData.RequestsBypassedPerSecond = domainData.BypassedRequests - domainData.PrevBypassed

	domainData.PrevRequests = domainData.TotalRequests
	domainData.PrevBypassed = domainData.BypassedRequests

	if !domainData.StageManuallySet || (domainData.BufferCooldown > 0) {

		// Log requests if a bypassing or raw attack is ongoing
		if domainData.BufferCooldown > 0 {
			if domainData.RequestsPerSecond > domainData.PeakRequestsPerSecond {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
			}
			if domainData.RequestsBypassedPerSecond > domainData.PeakRequestsBypassedPerSecond {
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
			}
			domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
				Time:     time.Now(),
				Allowed:  domainData.RequestsBypassedPerSecond,
				Total:    domainData.RequestsPerSecond,
				CpuUsage: proxy.CpuUsage,
			})
		}

		settingQuery, _ := domains.DomainsMap.Load(domainName)
		domainSettings := settingQuery.(domains.DomainSettings)

		if !domainData.BypassAttack && !domainData.RawAttack && (domainData.BufferCooldown > 0) {
			domainData.BufferCooldown--

			if domainData.BufferCooldown == 0 {
				go utils.SendAlerts(domainData, domainSettings, int(1))
				// Snapshot the finished attack BEFORE the peaks and
				// request logger below are reset. The export copies
				// the firewall tallies from a goroutine, so it never
				// takes the write lock held by this loop.
				reports.ExportOnAttackEnd(domainName, domainData)
				logging.Log(logging.Entry{Event: "attack_end", Domain: domainName, Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond, PeakRPS: domainData.PeakRequestsPerSecond, PeakRPSAllowed: domainData.PeakRequestsBypassedPerSecond})
				// Attack timeline (Batch 7): finish the
				// current attack with the monitor's peaks,
				// before they are reset below.
				timeline.EndAttack(domainName, timeline.Event{Kind: "attack_end", Detail: "attack ended, cooldown expired", Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond}, domainData.PeakRequestsPerSecond, domainData.PeakRequestsBypassedPerSecond)
				domainData.PeakRequestsPerSecond = 0
				domainData.PeakRequestsBypassedPerSecond = 0
				domainData.RequestLogger = []domains.RequestLog{}
			}
		}

		switch domainData.Stage {
		case 1:
			// A Bypassing Attack Started
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage1 && !domainData.BypassAttack {
				domainData.BypassAttack = true
				domainData.Stage = 2
				if domainData.BufferCooldown == 0 {
					domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
					domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
					domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
						Time:     time.Now(),
						Allowed:  domainData.RequestsBypassedPerSecond,
						Total:    domainData.RequestsPerSecond,
						CpuUsage: proxy.CpuUsage,
					})
					go utils.SendAlerts(domainData, domainSettings, int(0))
					logging.Log(logging.Entry{Event: "attack_start", Domain: domainName, Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond, PeakRPS: domainData.PeakRequestsPerSecond, PeakRPSAllowed: domainData.PeakRequestsBypassedPerSecond})
					// Attack timeline (Batch 7): a bypassing
					// attack started; stage moved 1 -> 2.
					timeline.StartAttack(domainName, timeline.Event{Kind: "attack_start", Detail: "bypassing attack started, escalated to stage 2", Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})
					//Challenge rotation (Batch 6): a new wave begins.
					advanceChallengeRotation(domainName, domainSettings)
				}
				// Start/Set cooldown
				domainData.BufferCooldown = 10
			}
		case 2:
			// Stage 2 is getting bypassed
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage2 {
				domainData.Stage = 3
				timeline.RecordEvent(domainName, timeline.Event{Kind: "stage_change", Detail: "stage 2 bypassed, escalated to stage 3", Stage: 3, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})

				// Stage 2 is no longer getting bypassed
			} else if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage2 && domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.BypassAttack {
				domainData.BypassAttack = false
				domainData.RawAttack = false
				domainData.Stage = 1
				timeline.RecordEvent(domainName, timeline.Event{Kind: "stage_change", Detail: "attack subsided, de-escalated to stage 1", Stage: 1, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})
			}
		case 3:
			// Stage 3 is no longer getting bypassed
			if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage3 && domainData.RequestsPerSecond < domainSettings.DisableRawStage3 {
				domainData.Stage = 2
				timeline.RecordEvent(domainName, timeline.Event{Kind: "stage_change", Detail: "stage 3 no longer bypassed, de-escalated to stage 2", Stage: 2, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})
			}
		}

		// An attack that didnt bypass was started
		if domainData.RequestsPerSecond > domainSettings.DisableRawStage2 && !domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = true

			if domainData.BufferCooldown == 0 {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
				domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
					Time:     time.Now(),
					Allowed:  domainData.RequestsBypassedPerSecond,
					Total:    domainData.RequestsPerSecond,
					CpuUsage: proxy.CpuUsage,
				})
				go utils.SendAlerts(domainData, domainSettings, int(0))
				logging.Log(logging.Entry{Event: "attack_start", Domain: domainName, Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond, PeakRPS: domainData.PeakRequestsPerSecond, PeakRPSAllowed: domainData.PeakRequestsBypassedPerSecond})
				// Attack timeline (Batch 7): a raw (non-bypassing)
				// attack started.
				timeline.StartAttack(domainName, timeline.Event{Kind: "attack_start", Detail: "raw attack started", Stage: domainData.Stage, RPS: domainData.RequestsPerSecond, RPSAllowed: domainData.RequestsBypassedPerSecond})
				//Challenge rotation (Batch 6): a new wave begins.
				advanceChallengeRotation(domainName, domainSettings)
			}

			//Set/Start cooldown
			domainData.BufferCooldown = 10
		} else if domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = false
		}

	}

	domains.DomainsData[domainName] = domainData
}

func printStats() {

	proxy.LastSecondTime = time.Now()
	proxy.LastSecondTimeFormated = proxy.LastSecondTime.Format("15:04:05")
	proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix())
	proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()
	proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)

	result, err := cpu.Percent(0, false)
	if err != nil {
		proxy.CpuUsage = "ERR"
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(err.Error()) + " ]")
	} else if len(result) > 0 {
		proxy.CpuUsage = fmt.Sprintf("%.2f", result[0])
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(proxy.CpuUsage) + " ]")
	} else {
		proxy.CpuUsage = "ERR_S0"
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor("100.00 ( Speculated )") + " ]")
	}

	//Not printed yet but calculated ram usage in %

	var ramStats runtime.MemStats
	runtime.ReadMemStats(&ramStats)

	// Calculate the current memory usage in percentage
	proxy.RamUsage = fmt.Sprintf("%.2f", float64(ramStats.Alloc)/float64(ramStats.Sys)*100)

	fmt.Println("")

	firewall.Mutex.RLock()
	domainData := domains.DomainsData[proxy.WatchedDomain]
	firewall.Mutex.RUnlock()

	if domainData.Stage == 0 && proxy.WatchedDomain != "debug" {
		if proxy.WatchedDomain != "" {
			fmt.Println("[" + utils.PrimaryColor("!") + "] [ " + utils.PrimaryColor("Domain \""+proxy.WatchedDomain+"\" Not Found") + " ]")
			fmt.Println("")
		}
		fmt.Println("[" + utils.PrimaryColor("Available Domains") + "]")
		counter := 0
		for _, dName := range domains.Domains {
			if counter < proxy.MaxLogLength {
				fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor(dName) + " ]")
				counter++
			}
		}
	} else if helpMode {
		fmt.Println("[" + utils.PrimaryColor("Available Commands") + "]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("help") + " ]: " + utils.PrimaryColor("Displays all available commands. More detailed information can be found at ") + "https://github.com/sonudigitalmindset-design/SonuShield#commands")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("stage") + " ]: " + utils.PrimaryColor("Usage: ") + "stage [number] " + utils.PrimaryColor("Locks the stage to the specified number. Use ") + "stage 0 " + utils.PrimaryColor("to unlock the stage"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("domain") + " ]: " + utils.PrimaryColor("Usage: ") + "domain [name] " + utils.PrimaryColor("Switch between your domains. Type only ") + "domain " + utils.PrimaryColor("to list all available domains"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("add") + " ]: " + utils.PrimaryColor("Usage: ") + "add " + utils.PrimaryColor("Starts a dialouge to add another domain to the proxy"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("clrlogs") + " ]: " + utils.PrimaryColor("Usage: ") + "clrlogs " + utils.PrimaryColor("Clears all logs for the current domain"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("reload") + " ]: " + utils.PrimaryColor("Usage: ") + "reload " + utils.PrimaryColor("Reload your proxy in order for changes in your ") + "config.json " + utils.PrimaryColor("to take effect"))
	} else {

		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Domain") + " ] > [ " + utils.PrimaryColor(proxy.WatchedDomain) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.Stage)) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage Locked") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.StageManuallySet)) + " ]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Total") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsPerSecond)+" r/s") + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Bypassed") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsBypassedPerSecond)+" r/s") + " ]")

		fmt.Println("")
		fmt.Println("[ " + utils.PrimaryColor("Latest Logs") + " ]")

		utils.ReadLogs(proxy.WatchedDomain)
	}

	utils.MoveInputLine()
}

func commands() {

	defer pnc.PanicHndl()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		if scanner.Scan() {

			PrintMutex.Lock()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("\033[K[ " + utils.PrimaryColor("Command") + " ]: \033[s")

			input := scanner.Text()
			details := strings.Split(input, " ")

			firewall.Mutex.RLock()
			domainData := domains.DomainsData[proxy.WatchedDomain]
			firewall.Mutex.RUnlock()
			helpMode = false

			switch details[0] {
			case "stage":

				if domainData.Stage == 0 {
					break
				}
				if !(len(details) > 1) {
					break
				}
				setStage, err := strconv.ParseInt(details[1], 0, 64)
				if err != nil {
					break
				}
				stage := int(setStage)
				if stage == 0 {
					domainData.Stage = 1
					domainData.StageManuallySet = false

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				} else {
					domainData.Stage = stage
					domainData.StageManuallySet = true

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				}
			case "domain":
				if len(details) < 2 {
					proxy.WatchedDomain = ""
				} else {
					proxy.WatchedDomain = details[1]
				}

				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "add":
				screen.Clear()
				screen.MoveTopLeft()
				utils.AddDomain()
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
				ReloadConfig()
			case "clrlogs":
				screen.Clear()
				screen.MoveTopLeft()
				if proxy.WatchedDomain == "" {
					for _, domain := range domains.Domains {
						firewall.Mutex.Lock()
						utils.ClearLogs(domain)
						firewall.Mutex.Unlock()
					}
					fmt.Println("[ " + utils.PrimaryColor("Clearing Logs All Domains ") + " ] ...")
				} else {
					firewall.Mutex.Lock()
					utils.ClearLogs(proxy.WatchedDomain)
					firewall.Mutex.Unlock()
					fmt.Println("[ " + utils.PrimaryColor("Clearing Logs For "+proxy.WatchedDomain) + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "reload":
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Reloading Proxy") + " ] ...")
				ReloadConfig()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "help":
				helpMode = true
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			default:
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			}
			PrintMutex.Unlock()
		}
	}
}

// This would ideally be in package config, however import cycles seem to not allow this.
//
// ReloadConfig re-reads config.json from disk and applies it. It is
// the terminal "reload" path: an unreadable or malformed file panics,
// exactly like the bad-rule and bad-certificate panics in the apply
// step below. API callers must use SafeReload (reload.go) instead,
// which validates first and never panics.
func ReloadConfig() {

	file, err := os.Open("config.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	var cfg domains.Configuration
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		panic(err)
	}
	reloadFromConfig(&cfg)
}

// reloadFromConfig applies an already-parsed configuration to the
// running proxy: secrets, timeouts, GeoIP, reputation, logging,
// per-domain proxies, certificates, firewall rules, and the auto-SSL
// manager. It resets per-domain counters and stage state, exactly
// like the terminal reload always has. Callers must validate cfg
// first (ValidateConfig) unless a panic on bad input is acceptable:
// an uncompilable rule or unloadable certificate below panics.
func reloadFromConfig(cfg *domains.Configuration) {

	domains.Config = cfg
	domains.Domains = []string{}

	// Privacy mode (Batch 7): set before logging.Configure
	// runs below, mirroring Load.
	privacy.Set(domains.Config.Proxy.PrivacyMode)

	proxy.Cloudflare = domains.Config.Proxy.Cloudflare

	proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]
	proxy.JSSecret = domains.Config.Proxy.Secrets["javascript"]
	proxy.CaptchaSecret = domains.Config.Proxy.Secrets["captcha"]

	// Dashboard mode (platform model): re-applied on reload
	// so a migration (local -> control-plane -> off) takes
	// effect through the control panel without a restart.
	// These are not secrets, unlike the API/admin secrets
	// above, which stay load-only by design.
	proxy.DashboardMode = domains.Config.Proxy.DashboardMode
	proxy.ControlPlaneURL = domains.Config.Proxy.ControlPlaneURL

	// Role-mapped API secrets (Batch 4): a reload picks up role
	// changes, like the other secrets above.
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

	if len(domains.Config.Proxy.Colors) != 0 {
		utils.SetColor(domains.Config.Proxy.Colors)
	}

	if domains.Config.Proxy.GeoIPCountryDB != "" || domains.Config.Proxy.GeoIPASNDB != "" {
		if geoErr := firewall.InitGeoIP(domains.Config.Proxy.GeoIPCountryDB, domains.Config.Proxy.GeoIPASNDB); geoErr != nil {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Failed to open GeoIP database, Geo/ASN rules will not match: " + geoErr.Error() + " ]")
		}
	}

	firewall.InitReputation(domains.Config.Proxy.ReputationList, domains.Config.Proxy.ReputationFeed, domains.Config.Proxy.ReputationIntvl, domains.Config.Proxy.ReputationSusLv)
	sharing.Configure(domains.Config.Proxy.ThreatSharing)
	oncalls.Configure(domains.Config.Proxy.OnCall)

	// Per-IP connection cap (Batch 5, slowloris guard). Re-applied
	// on reload so cap changes take effect without a restart.
	firewall.SetMaxConnsPerIP(domains.Config.Proxy.MaxConnsPerIP)

	// Passive OS signatures (Batch 7). Re-applied on reload.
	firewall.SetOSSignatures(domains.Config.Proxy.OSSignatures)

	// Structured JSON logging (Batch 2). Re-applied on reload so new
	// log settings take effect without a restart.
	logging.Configure(domains.Config.Proxy.LogFormat, domains.Config.Proxy.LogFile, domains.Config.Proxy.LogMaxBytes, domains.Config.Proxy.LogMaxFiles)

	proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.Config.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.Config.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.Config.Proxy.Ratelimits["noRequestsSent"]

	for i, domain := range domains.Config.Domains {
		domains.Domains = append(domains.Domains, domain.Name)

		firewallRules := []domains.Rule{}
		rawFirewallRules := domains.Config.Domains[i].FirewallRules
		for index, fwRule := range domains.Config.Domains[i].FirewallRules {

			rule, err := gofilter.NewFilter(fwRule.Expression)
			if err != nil {
				panic("[ " + utils.PrimaryColor("!") + " ] [ Error Loading Custom Firewall Rules: " + utils.PrimaryColor(err.Error()) + " ]")
			}

			//Scheduled rules (Batch 7): an invalid schedule
			//warns and leaves the rule always active (fail
			//safe), mirroring Load.
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
		//lenient parsing, mirroring Load.
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
		dProxy.Transport = &RoundTripper{}
		dProxy.ModifyResponse = ModifyResponseHook

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

			BypassStage1:         domain.BypassStage1,
			BypassStage2:         domain.BypassStage2,
			DisableBypassStage3:  domain.DisableBypassStage3,
			DisableRawStage3:     domain.DisableRawStage3,
			DisableBypassStage2:  domain.DisableBypassStage2,
			DisableRawStage2:     domain.DisableRawStage2,
			AdaptivePow:          domain.AdaptivePow,
			PoWDifficultyMin:     domain.PoWDifficultyMin,
			PoWDifficultyMax:     domain.PoWDifficultyMax,
			MemoryHardPow:        domain.MemoryHardPow,
			MemoryHardPowBits:    domain.MemoryHardPowBits,
			MemoryHardPowMemory:  domain.MemoryHardPowMemory,
			MemoryHardPowTime:    domain.MemoryHardPowTime,
			ChallengeProvider:    domain.ChallengeProvider,
			ChallengeSiteKey:     domain.ChallengeSiteKey,
			ChallengeSecretKey:   domain.ChallengeSecretKey,
			ChallengeRotation:    domain.ChallengeRotation,
			ChallengeRotationMode: domain.ChallengeRotationMode,
			WAFMode:              domain.WAFMode,
			WAFInspectBody:       domain.WAFInspectBody,
			WAFWpLoginLimit:      domain.WAFWpLoginLimit,
			HoneypotPaths:        domain.HoneypotPaths,
			HoneypotSusLv:        domain.HoneypotSusLv,
			CanaryPaths:          domain.CanaryPaths,
			CanaryTokens:         domain.CanaryTokens,
			SignedURLSecret:      domain.SignedURLSecret,
			SignedURLPaths:       domain.SignedURLPaths,
			HotlinkProtect:       domain.HotlinkProtect,
			HotlinkPaths:         domain.HotlinkPaths,
			HotlinkAllowlist:     domain.HotlinkAllowlist,
			FormGuard:           domain.FormGuard,
			CredentialStuffing:  domain.CredentialStuffing,
			SessionHijack:       domain.SessionHijack,
			SLATarget:           domain.SLATarget,
			FakeBotCheck:         domain.FakeBotCheck,
			FakeBotSusLv:         domain.FakeBotSusLv,
			TarpitDelayMs:        domain.TarpitDelayMs,
			TarpitSusLv:          domain.TarpitSusLv,
			TarpitMaxConns:       domain.TarpitMaxConns,
			EdgeCache:            domain.EdgeCache,
			EdgeCacheTTL:         domain.EdgeCacheTTL,
			EdgeCacheMaxMB:       domain.EdgeCacheMaxMB,
			Brotli:               domain.Brotli,
			ImageOptimize:        domain.ImageOptimize,
			ImageOptimizeMaxWidth: domain.ImageOptimizeMaxWidth,
			ImageOptimizeQuality: domain.ImageOptimizeQuality,
			StampedeGuard:        domain.StampedeGuard,
			WaitingRoom:          domain.WaitingRoom,
			WaitingRoomThreshold: domain.WaitingRoomThreshold,
			WaitingRoomAdmit:     domain.WaitingRoomAdmit,
			Backends:             domain.Backends,
			LBPolicy:             domain.LBPolicy,
			HealthCheckEnabled:   domain.HealthCheckEnabled,
			HealthCheckPath:      domain.HealthCheckPath,
			HealthCheckInterval:  domain.HealthCheckInterval,
			PoolMaxIdleConns:     domain.PoolMaxIdleConns,
			PoolMaxIdleConnsPerHost: domain.PoolMaxIdleConnsPerHost,
			PoolMaxConnsPerHost:  domain.PoolMaxConnsPerHost,
			PoolIdleConnTimeout:  domain.PoolIdleConnTimeout,
			WebsocketIdleTimeout: domain.WebsocketIdleTimeout,
			JWTProtectedPaths:    domain.JWTProtectedPaths,
			APIKeyHeader:         domain.APIKeyHeader,
			APIKeyPaths:          domain.APIKeyPaths,
			GraphQLPath:          domain.GraphQLPath,
			GraphQLMaxDepth:      domain.GraphQLMaxDepth,
			GraphQLMaxFields:     domain.GraphQLMaxFields,
			Passkey:              domain.Passkey,
			RulesDryRun:          domain.RulesDryRun,
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

		if domain.Stage2Difficulty == 0 {
			domain.Stage2Difficulty = 5
		}

		firewall.Mutex.Lock()
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
	// when at least one domain opted in, re-evaluated on every
	// reload like the other proxy-wide switches above.
	sharedRepEnabled := false
	for _, domain := range domains.Config.Domains {
		if domain.ShareReputation {
			sharedRepEnabled = true
			break
		}
	}
	firewall.SetSharedReputationEnabled(sharedRepEnabled)

	// Auto SSL: build the Let's Encrypt manager from the final domain
	// list. Disabled by default; in Cloudflare mode there is no TLS
	// listener, so the option is ignored with a warning.
	if domains.Config.Proxy.AutoSSL && proxy.Cloudflare {
		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ autoSSL is enabled but Cloudflare mode has no TLS listener; automatic certificates are disabled. ]")
	}
	domains.ConfigureAutoCert()

	// Origin pooling (Batch 6): drop cached per-domain Transports
	// so pool settings changed by this reload take effect on the
	// next request. In-flight requests keep their Transport.
	resetOriginTransports()

	proxy.WatchedDomain = domains.Domains[0]
}

func clearProxyCache() {

	defer pnc.PanicHndl()

	for {
		//Clear logs and maps every 2 minutes. (I know this is a lazy way to do it, tho for now it seems to be the most efficient and fast way to go about it)
		firewall.Mutex.Lock()

		proxyCpuUsage, pcuErr := strconv.ParseFloat(proxy.CpuUsage, 32)
		if pcuErr != nil {
			proxyCpuUsage = 0
		}

		proxyMemUsage, pmuErr := strconv.ParseFloat(proxy.RamUsage, 32)
		if pmuErr != nil {
			proxyMemUsage = 0
		}

		// Only clear if proxy isnt under attack / memory is running out
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheIps.Range(func(key, value any) bool {
				firewall.CacheIps.Delete(key)
				return true
			})
		}
		// Same for here
		imgCachelen := 0
		firewall.CacheImgs.Range(func(key, value any) bool {
			imgCachelen++
			return true
		})
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheImgs.Range(func(key, value any) bool {
				firewall.CacheImgs.Delete(key)
				return true
			})
		}
		firewall.Mutex.Unlock()
		time.Sleep(2 * time.Minute)
	}
}

// Iterate through the slider every 5 seconds
func evaluateRatelimit() {
	for {

		firewall.Mutex.Lock()
		//Initialise Maps before they're ever written, as to save if statements during potential attack
		for i := proxy.Last10SecondTimestamp; i < proxy.Last10SecondTimestamp+120; i = i + 10 {
			if firewall.WindowAccessIps[i] == nil {
				//log.Printf("Set AccessIPs Windows For %d", i)
				firewall.WindowAccessIps[i] = map[string]int{}
			}
			if firewall.WindowAccessIpsCookie[i] == nil {
				//log.Printf("Set AccessIPsCookie Windows For %d", i)
				firewall.WindowAccessIpsCookie[i] = map[string]int{}
			}
			if firewall.WindowUnkFps[i] == nil {
				//log.Printf("Set AccessUnkFps Windows For %d", i)
				firewall.WindowUnkFps[i] = map[string]int{}
			}
		}

		// Delete outdated records & calculate requests for every ip
		firewall.AccessIps = map[string]int{}
		for windowTime, accessIPs := range firewall.WindowAccessIps {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
				//log.Printf("Deleting AccessIPs Windows For %d", windowTime)
				delete(firewall.WindowAccessIps, windowTime)
			} else {
				for IP, requests := range accessIPs {
					firewall.AccessIps[IP] += requests
				}
			}
		}
		firewall.AccessIpsCookie = map[string]int{}
		for windowTime, accessIPsCookie := range firewall.WindowAccessIpsCookie {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
				//log.Printf("Deleting AccessIPsCookie Windows For %d", windowTime)
				delete(firewall.WindowAccessIpsCookie, windowTime)
			} else {
				for IP, requests := range accessIPsCookie {
					firewall.AccessIpsCookie[IP] += requests
				}
			}
		}
		firewall.UnkFps = map[string]int{}
		for windowTime, unkFps := range firewall.WindowUnkFps {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
				//log.Printf("Deleting AccessUnkFps Windows For %d", windowTime)
				delete(firewall.WindowUnkFps, windowTime)
			} else {
				for IP, requests := range unkFps {
					firewall.UnkFps[IP] += requests
				}
			}
		}
		firewall.Mutex.Unlock()
		proxy.Initialised = true

		//log.Printf("I Ran. I'm supposed to run every 5 seconds. If that didn't happen we're in deep shit")
		time.Sleep(5 * time.Second)

	}
}

func generateOTPSecrets() {

	defer pnc.PanicHndl()

	//You can change this to use hours as the hash key, to make it even more secure against offline bruteforcing, however, if you use multiple servers make sure they all start within the same timeframe, e.g.
	//Server1 starts at 23:59:50, Server2 starts at 00:00:01. In this case the keys are mismatched and clients would have to solve challenges again whenever they access a different server than before.
	//To avoid this and help you, this function runs every minute, reducing this offset to only 1 minute maximum of mismatch per day
	//This has now been changed to an hour, for better performance

	for {

		currTime := time.Now()
		currDate := currTime.Format("2006-01-02")

		proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, currDate)
		proxy.JSOTP = utils.EncryptSha(proxy.JSSecret, currDate)
		proxy.CaptchaOTP = utils.EncryptSha(proxy.CaptchaSecret, currDate)

		time.Sleep(1 * time.Hour)
	}
}
