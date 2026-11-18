package utils

// Twilio-compatible WhatsApp/SMS alerts (Batch 6).
//
// Sends attack start/end messages through the operator's own
// Twilio (or Twilio-compatible) account. Credentials come only
// from the operator's config.json (per-domain "twilio" settings);
// the feature is inert when any of the account SID, auth token,
// from, or to value is missing. Whether a message goes via
// WhatsApp or SMS is decided by the provider from the From/To
// values: addresses prefixed with "whatsapp:" go via WhatsApp,
// plain E.164 numbers go via SMS — no separate switch exists.
// The API base defaults to https://api.twilio.com and can be
// overridden (apiBase) for compatible providers that implement
// the same Messages endpoint. The auth token is sent only as
// HTTP Basic auth and is never logged: failures print a generic
// line with no error detail, because error strings can echo
// request data. No message content is ever logged.

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sonushield/core/domains"
	"sonushield/core/pnc"
	"strings"
	"time"
)

func SendTwilio(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {
	defer pnc.PanicHndl()

	twilio := domainSettings.DomainTwilio
	if twilio.AccountSID == "" || twilio.AuthToken == "" || twilio.From == "" || twilio.To == "" {
		return
	}

	template := twilio.AttackStartMsg
	if notificationType == 1 {
		template = twilio.AttackStopMsg
	}
	text := alertText(template, domainData, domainSettings.Name, notificationType)

	sendTwilioText(twilio, text)
}

// sendTwilioText posts one message through the operator's
// Twilio-compatible account. It is the shared transport for
// attack alerts and generic notices (utils.SendNotice); the
// auth token is sent only as HTTP Basic auth and is never
// logged.
func sendTwilioText(twilio domains.TwilioSettings, text string) {
	if twilio.AccountSID == "" || twilio.AuthToken == "" || twilio.From == "" || twilio.To == "" {
		return
	}

	base := strings.TrimRight(twilio.APIBase, "/")
	if base == "" {
		base = "https://api.twilio.com"
	}
	endpoint := base + "/2010-04-01/Accounts/" + twilio.AccountSID + "/Messages.json"

	form := url.Values{}
	form.Set("From", twilio.From)
	form.Set("To", twilio.To)
	form.Set("Body", text)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(twilio.AccountSID, twilio.AuthToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[ ! ] [ Twilio alert failed ]")
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Println("[ ! ] [ Twilio alert failed ]")
	}
}
