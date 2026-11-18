package synthetic

// Synthetic self-checks (Batch 8).
//
// RunOnce executes every configured check: one HTTP request
// per check with the distinctive user-agent
// "SonuShield-Synthetic-Check/1.0", a 15-second timeout, and
// at most 3 redirects. TLS is always verified. A check passes
// when the request succeeds, the status matches the expected
// status (200 by default), and the expected body substring
// (when configured) is present. Latency is measured from
// request start to body read completion, capped at a 1 MB
// body read.
//
// Alert semantics: the first run for a check is a silent
// baseline. A later failure alerts once, on the transition
// from passing to failing; a recovery alerts once. A latency
// breach (when a threshold is configured) alerts once per
// transition in the same way, independently of the
// pass/fail state. While a check keeps failing, no further
// alerts are raised — the status API shows the ongoing
// failure. Checks never touch attack statistics.

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// UserAgent identifies synthetic check requests in logs.
const UserAgent = "SonuShield-Synthetic-Check/1.0"

const (
	checkTimeout  = 15 * time.Second
	maxRedirects  = 3
	maxCheckBody  = 1 << 20
)

// CheckState is the monitored state of one check.
type CheckState struct {
	Name                 string
	URL                  string
	LastRun              time.Time
	LastOK               bool
	LastLatencyMs        int64
	LastError            string
	ConsecutiveFailures  int
	LatencyBreaching     bool
	Seen                 bool
}

// Event is one alert produced by a run: Kind is "failure",
// "recovery", "latency", or "latency_recovery".
type Event struct {
	Name   string
	Kind   string
	Detail string
}

var (
	mu     sync.Mutex
	states = map[string]*CheckState{}

	httpClient = &http.Client{
		Timeout: checkTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
)

// RunOnce executes every check in checks and returns the
// alert events produced. latencyThresholdMs <= 0 disables
// latency alerting.
func RunOnce(checks []CheckSpec, latencyThresholdMs int) []Event {
	mu.Lock()
	defer mu.Unlock()
	var events []Event
	now := time.Now().UTC()
	for _, check := range checks {
		state, ok := states[check.Name]
		if !ok {
			state = &CheckState{Name: check.Name}
			states[check.Name] = state
		}
		state.URL = check.URL
		wasFailing := state.Seen && !state.LastOK
		latencyMs, err := runCheck(check)
		state.LastRun = now
		state.LastLatencyMs = latencyMs
		if err != nil {
			state.LastError = err.Error()
			state.ConsecutiveFailures++
			state.LastOK = false
		} else {
			state.LastError = ""
			state.ConsecutiveFailures = 0
			state.LastOK = true
		}
		if !state.Seen {
			state.Seen = true
			state.LatencyBreaching = latencyThresholdMs > 0 && latencyMs > int64(latencyThresholdMs)
			continue
		}
		if err != nil && !wasFailing {
			events = append(events, Event{Name: check.Name, Kind: "failure", Detail: err.Error()})
		} else if err == nil && wasFailing {
			events = append(events, Event{Name: check.Name, Kind: "recovery", Detail: fmt.Sprintf("check passing again after failure (latency %d ms)", latencyMs)})
		}
		// Latency transitions, independent of pass/fail.
		if latencyThresholdMs > 0 {
			breaching := latencyMs > int64(latencyThresholdMs)
			if breaching && !state.LatencyBreaching {
				state.LatencyBreaching = true
				events = append(events, Event{Name: check.Name, Kind: "latency", Detail: fmt.Sprintf("latency %d ms exceeds threshold %d ms", latencyMs, latencyThresholdMs)})
			} else if !breaching && state.LatencyBreaching {
				state.LatencyBreaching = false
				events = append(events, Event{Name: check.Name, Kind: "latency_recovery", Detail: fmt.Sprintf("latency %d ms back under threshold %d ms", latencyMs, latencyThresholdMs)})
			}
		}
	}
	return events
}

// CheckSpec is the runnable form of one configured check.
type CheckSpec struct {
	Name               string
	URL                string
	Method             string
	ExpectStatus       int
	ExpectBodyContains string
}

func runCheck(check CheckSpec) (int64, error) {
	method := strings.ToUpper(check.Method)
	if method != http.MethodGet && method != http.MethodHead {
		method = http.MethodGet
	}
	expectStatus := check.ExpectStatus
	if expectStatus == 0 {
		expectStatus = http.StatusOK
	}
	request, err := http.NewRequest(method, check.URL, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", UserAgent)
	start := time.Now()
	response, err := httpClient.Do(request)
	if err != nil {
		return time.Since(start).Milliseconds(), err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCheckBody+1))
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		return latencyMs, err
	}
	if response.StatusCode != expectStatus {
		return latencyMs, fmt.Errorf("status %d, expected %d", response.StatusCode, expectStatus)
	}
	if check.ExpectBodyContains != "" && !strings.Contains(string(body), check.ExpectBodyContains) {
		return latencyMs, fmt.Errorf("body does not contain %q", check.ExpectBodyContains)
	}
	return latencyMs, nil
}

// Status returns a snapshot of every check's state.
func Status() []CheckState {
	mu.Lock()
	defer mu.Unlock()
	out := make([]CheckState, 0, len(states))
	for _, state := range states {
		out = append(out, *state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
