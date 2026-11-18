// Package certmon holds the state for certificate-expiry and
// subdomain-monitoring alerts (Batch 7). It is deliberately
// neutral: the server package runs the background loop and
// delivers alerts, the API package reads status, and neither
// may import the other.
//
// Certificate alerts are deduplicated to at most one alert
// per certificate file per calendar day. Subdomain
// monitoring treats the first successful resolution as a
// silent baseline: only a later change of the address set,
// or N consecutive resolution failures, alerts. Everything
// here fails open: a lookup or file error never blocks
// traffic and is recorded in status for the operator.
package certmon

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var errNoPEM = errors.New("no PEM block found")

// CertAlert records the last alert sent for one certificate
// file, for status reporting.
type CertAlert struct {
	Path      string    `json:"path"`
	LastAlert time.Time `json:"last_alert"`
}

// SubdomainStatus is the recorded state of one monitored
// name. Addresses is the last observed address set; on the
// first observation it becomes the silent baseline.
type SubdomainStatus struct {
	Name                string    `json:"name"`
	Addresses           []string  `json:"addresses"`
	BaselineSet         bool      `json:"baseline_set"`
	LastChecked         time.Time `json:"last_checked"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastError           string    `json:"last_error,omitempty"`
	FailureAlerted      bool      `json:"failure_alerted"`
	LastChangeAlert     time.Time `json:"last_change_alert,omitempty"`
}

var (
	mu             sync.RWMutex
	certAlerts     = map[string]time.Time{}
	subdomainState = map[string]*SubdomainStatus{}
)

// ShouldAlertCert reports whether an expiry alert for path
// may be sent now, and records the alert when it may. At
// most one alert per path per calendar day (local time) is
// allowed; callers check this before sending.
func ShouldAlertCert(path string, now time.Time) bool {
	mu.Lock()
	defer mu.Unlock()
	last, ok := certAlerts[path]
	if ok && sameDay(last, now) {
		return false
	}
	certAlerts[path] = now
	return true
}

// CertAlerts returns a copy of the recorded certificate
// alerts, newest first.
func CertAlerts() []CertAlert {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]CertAlert, 0, len(certAlerts))
	for path, when := range certAlerts {
		out = append(out, CertAlert{Path: path, LastAlert: when})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAlert.After(out[j].LastAlert) })
	return out
}

// LastCertAlert returns the last alert time for path, if any.
func LastCertAlert(path string) (time.Time, bool) {
	mu.RLock()
	defer mu.RUnlock()
	when, ok := certAlerts[path]
	return when, ok
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// LookupOutcome describes what one DNS observation means.
type LookupOutcome struct {
	// Changed is true when the address set differs from the
	// recorded baseline (never true for the first
	// observation, which silently sets the baseline).
	Changed bool
	// Previous holds the baseline address set when Changed.
	Previous []string
	// FailureAlert is true when consecutive failures just
	// reached the threshold and no failure alert is
	// outstanding for this name.
	FailureAlert bool
}

// RecordLookup folds one DNS observation into the state for
// name and reports what, if anything, the caller should
// alert on. addrs is the resolved address set on success;
// err is non-nil on failure. failureThreshold is clamped to
// a minimum of 1 by the caller.
func RecordLookup(name string, addrs []string, err error, failureThreshold int, now time.Time) LookupOutcome {
	mu.Lock()
	defer mu.Unlock()
	state, ok := subdomainState[name]
	if !ok {
		state = &SubdomainStatus{Name: name}
		subdomainState[name] = state
	}
	state.LastChecked = now
	if err != nil {
		state.ConsecutiveFailures++
		state.LastError = err.Error()
		outcome := LookupOutcome{}
		if state.ConsecutiveFailures >= failureThreshold && !state.FailureAlerted {
			state.FailureAlerted = true
			outcome.FailureAlert = true
		}
		return outcome
	}
	state.ConsecutiveFailures = 0
	state.LastError = ""
	state.FailureAlerted = false
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)
	outcome := LookupOutcome{}
	if !state.BaselineSet {
		// First observation: silent baseline.
		state.BaselineSet = true
		state.Addresses = sorted
		return outcome
	}
	if !equalStrings(state.Addresses, sorted) {
		outcome.Changed = true
		outcome.Previous = append([]string(nil), state.Addresses...)
		state.Addresses = sorted
		state.LastChangeAlert = now
	}
	return outcome
}

// SubdomainStatuses returns copies of all recorded
// subdomain states, sorted by name.
func SubdomainStatuses() []SubdomainStatus {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]SubdomainStatus, 0, len(subdomainState))
	for _, state := range subdomainState {
		copy := *state
		copy.Addresses = append([]string(nil), state.Addresses...)
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Reset clears all recorded state. It exists for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	certAlerts = map[string]time.Time{}
	subdomainState = map[string]*SubdomainStatus{}
}

// ReadLeafCert parses the first PEM certificate in path. It
// is the single certificate reader for the monitor loop, the
// grade scan, and the status API.
func ReadLeafCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errNoPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

// DaysRemaining returns whole days until cert expires.
// Negative values mean it already expired.
func DaysRemaining(cert *x509.Certificate, now time.Time) int {
	return int(cert.NotAfter.Sub(now).Hours() / 24)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AddressSet formats an address list for alert text.
func AddressSet(addrs []string) string {
	if len(addrs) == 0 {
		return "(none)"
	}
	return strings.Join(addrs, ", ")
}
