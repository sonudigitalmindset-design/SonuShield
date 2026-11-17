package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/utils"
	"io/ioutil"
	"net/http"
	"strings"
)

func Generate() {

	fmt.Println("[ " + utils.PrimaryColor("No Configuration File Found") + " ]")
	fmt.Println("[ " + utils.PrimaryColor("Configuring Proxy Now") + " ]")
	fmt.Println("")

	gConfig := domains.Configuration{
		Proxy: domains.Proxy{
			Cloudflare:  utils.AskBool("Use This Proxy With Cloudflare? (y/N)", false),
			AdminSecret: utils.RandomString(25),
			APISecret:   utils.RandomString(30),
			Timeout: domains.TimeoutSettings{
				Idle:       utils.AskInt("How Many Seconds Should An Indle Connection Be Kept Open?", 3),
				Read:       utils.AskInt("How Many Seconds Should A Reading Connection Be Kept Open?", 5),
				Write:      utils.AskInt("How Many Seconds Should A Writing Connection Be Kept Open?", 5),
				ReadHeader: utils.AskInt("How Many Seconds Should Be Allowed To Read A Connections Header?", 5),
			},
			Secrets: map[string]string{
				"cookie":     utils.RandomString(20),
				"javascript": utils.RandomString(20),
				"captcha":    utils.RandomString(20),
			},
			Ratelimits: map[string]int{
				"requests":           utils.AskInt("After How Many Requests From An IP Within 2 Minutes Should It Be Blocked?", 1000),
				"unknownFingerprint": utils.AskInt("After How Many Requests From An Unknown Fingerprint Within 2 Minutes Should It Be Blocked?", 150),
				"challengeFailures":  utils.AskInt("After How Many Failed Attempts At Solving A Challenge From An IP Within 2 Minutes Should It Be Blocked?", 40),
				"noRequestsSent":     utils.AskInt("After How Many TCP Connection Attempts Without Sending A Http Request From An IP Within 2 Minutes Should It Be Blocked?", 10),
			},
		},
		Domains: []domains.Domain{},
	}

	domains.Config = &gConfig

	jsonConfig, err := json.Marshal(gConfig)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("config.json", jsonConfig, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("")
	AddDomain()
}

func AddDomain() {
	fmt.Println("[ " + utils.PrimaryColor("No Domain Configurations Found") + " ]")
	fmt.Println("[ " + utils.PrimaryColor("Configure New Domains In The Config.json") + " ]")
	fmt.Println("")
	gDomain := domains.Domain{
		Name:        utils.AskString("What Is The Name Of Your Domain (eg. \"example.com\")", "example.com"),
		Backend:     utils.AskString("What Is The Backed/Server The Proxy Should Proxy To?", "1.1.1.1"),
		Scheme:      strings.ToLower(utils.AskString("What Scheme Should The Proxy Use To Communicate With Your Backend? (http/https)", "http")),
		Certificate: utils.AskString("What Is The Path To The SSL Certificate For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Key:         utils.AskString("What Is The Path To The SSL Key For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Webhook: domains.WebhookSettings{
			URL:            utils.AskString("What Is The Url For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Name:           utils.AskString("What Is The Name For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Avatar:         utils.AskString("What Is The Url For Your Discord Webhook Avatar? (Leave Empty If You Do Not Want One)", ""),
			AttackStartMsg: utils.AskString("What Is The Message Your Webhook Should Send When Your Website Is Under Attack?", ""),
			AttackStopMsg:  utils.AskString("What Is The Message Your Webhook Should Send When Your Website Is No Longer Under Attack?", ""),
		},
		FirewallRules:       []domains.JsonRule{},
		BypassStage1:        utils.AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 2?", 75),
		Stage2Difficulty:    utils.AskInt("How difficult should Stage 2 Be? (6 AT MOST recommended)", 5),
		BypassStage2:        utils.AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 3?", 250),
		DisableBypassStage3: utils.AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 3?", 100),
		DisableRawStage3:    utils.AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 3? (Bypassing Requests Still Have To Be Low Enough)", 250),
		DisableBypassStage2: utils.AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 2?", 50),
		DisableRawStage2:    utils.AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 2? (Bypassing Requests Still Have To Be Low Enough)", 75),
	}

	domains.Config.Domains = append(domains.Config.Domains, gDomain)

	jsonConfig, err := json.Marshal(domains.Config)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("config.json", jsonConfig, 0644)
	if err != nil {
		panic(err)
	}
}

func GetFingerprints(url string, target *map[string]string) error {
	resp, err := http.Get(url)
	if err != nil {
		return errors.New("failed to fetch fingerprints: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New("failed to fetch fingerprints: " + err.Error())
	}

	err = json.Unmarshal(body, &target)
	if err != nil {
		return errors.New("failed to fetch fingerprints: " + err.Error())
	}
	return nil
}

// LoadJA4LocalOverrides merges operator-observed JA4 values from a local
// JSON file (next to config.json) over the fetched JA4 lists. Local entries
// win on key conflicts. The file is optional: when it does not exist this
// is a silent no-op, and when it fails to parse a warning is printed and
// the fetched lists are kept unchanged (fail-open).
//
// Expected format:
//
//	{
//	  "known": {"t13d...": "Chromium"},
//	  "bot": {"t13d...": "SomeBot"},
//	  "malicious": {"t13d...": "Flood tool"}
//	}
//
// Only JA4 values observed on your own proxy (see /_bProxy/fingerprint)
// belong here: SonuShield JA4 values are computed from the fields Go's
// TLS stack exposes and are not comparable with values from external
// JA4 databases. See global/fingerprints/SOURCES.md.
func LoadJA4LocalOverrides(path string) {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	var overrides struct {
		Known     map[string]string `json:"known"`
		Bot       map[string]string `json:"bot"`
		Malicious map[string]string `json:"malicious"`
	}
	if err := json.Unmarshal(body, &overrides); err != nil {
		fmt.Println("[ ! ] [ Failed to parse " + path + ", keeping fetched JA4 lists: " + err.Error() + " ]")
		return
	}

	merge := func(dst map[string]string, src map[string]string) {
		for key, value := range src {
			dst[key] = value
		}
	}
	merge(firewall.KnownJA4, overrides.Known)
	merge(firewall.BotJA4, overrides.Bot)
	merge(firewall.ForbiddenJA4, overrides.Malicious)
}
