package oncalls

// On-call rotation resolution and open-alert tracking
// (Batch 8).
//
// This package owns no transports: utils applies the
// resolution to alert delivery and runs the escalation
// ticker, because utils owns the channel senders and this
// package must not import utils (utils imports oncalls).
// Configure installs the rotation; Resolve answers "who is
// on call now" from the schedule; Track/Ack/DueEscalations
// manage the open-alert list used by ACK_ALERT and the
// escalation ticker.
//
// Resolution rules: the first schedule entry matching the
// current day and time (in the entry's timezone) wins. An
// entry matches when the current weekday is listed and the
// current time falls in [start, end); an end earlier than
// the start spans midnight (matching late hours on the
// listed day and early hours on the following day); equal
// start and end match the whole listed day. Invalid entries
// (unknown responder, unparseable times, no days) never
// match and are reported once at Configure time.

import (
	"fmt"
	"sonushield/core/domains"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpenAlert is one tracked alert awaiting acknowledgement.
type OpenAlert struct {
	ID        string
	Title     string
	Body      string
	Domain    string
	CreatedAt time.Time
	Acked     bool
	Escalated bool
}

var (
	mu      sync.Mutex
	cfg     domains.OnCallConfig
	alerts  = map[string]*OpenAlert{}
	counter int64
)

// Configure installs the rotation configuration and warns
// about entries that can never match. Stored alerts survive
// a reload.
func Configure(c domains.OnCallConfig) {
	mu.Lock()
	defer mu.Unlock()
	cfg = c
	if !c.Enabled {
		return
	}
	known := map[string]bool{}
	for _, responder := range c.Responders {
		known[responder.Name] = true
	}
	for i, entry := range c.Schedule {
		if !known[entry.Responder] {
			fmt.Println("[ ! ] [ on-call schedule entry " + strconv.Itoa(i) + ": unknown responder \"" + entry.Responder + "\" ]")
			continue
		}
		if len(entry.Days) == 0 {
			fmt.Println("[ ! ] [ on-call schedule entry " + strconv.Itoa(i) + ": no days listed ]")
		}
		if _, _, ok := parseHHMM(entry.Start); !ok {
			fmt.Println("[ ! ] [ on-call schedule entry " + strconv.Itoa(i) + ": invalid start time \"" + entry.Start + "\" ]")
		}
		if _, _, ok := parseHHMM(entry.End); !ok {
			fmt.Println("[ ! ] [ on-call schedule entry " + strconv.Itoa(i) + ": invalid end time \"" + entry.End + "\" ]")
		}
		if entry.Timezone != "" {
			if _, err := time.LoadLocation(entry.Timezone); err != nil {
				fmt.Println("[ ! ] [ on-call schedule entry " + strconv.Itoa(i) + ": unknown timezone \"" + entry.Timezone + "\", UTC will be used ]")
			}
		}
	}
}

// Enabled reports whether the rotation is active.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return cfg.Enabled && len(cfg.Responders) > 0 && len(cfg.Schedule) > 0
}

// EscalationMinutes reports the configured escalation delay,
// or 0 when escalation is off.
func EscalationMinutes() int {
	mu.Lock()
	defer mu.Unlock()
	if !cfg.Enabled || cfg.EscalationMinutes <= 0 {
		return 0
	}
	return cfg.EscalationMinutes
}

// Config returns a copy of the current configuration.
// Responder secrets stay in this copy; callers must never
// log or return it.
func Config() domains.OnCallConfig {
	mu.Lock()
	defer mu.Unlock()
	return cfg
}

// Responders returns the configured responders.
func Responders() []domains.OnCallResponder {
	mu.Lock()
	defer mu.Unlock()
	return append([]domains.OnCallResponder(nil), cfg.Responders...)
}

// Resolve returns the responder on call at now, or false
// when no entry matches.
func Resolve(now time.Time) (domains.OnCallResponder, bool) {
	mu.Lock()
	defer mu.Unlock()
	if !cfg.Enabled {
		return domains.OnCallResponder{}, false
	}
	byName := map[string]domains.OnCallResponder{}
	for _, responder := range cfg.Responders {
		byName[responder.Name] = responder
	}
	for _, entry := range cfg.Schedule {
		responder, ok := byName[entry.Responder]
		if !ok {
			continue
		}
		if entryMatches(entry, now) {
			return responder, true
		}
	}
	return domains.OnCallResponder{}, false
}

func parseHHMM(text string) (hour, minute int, ok bool) {
	parts := strings.Split(text, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	hour, err1 := strconv.Atoi(parts[0])
	minute, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, false
	}
	return hour, minute, true
}

func entryMatches(entry domains.OnCallEntry, now time.Time) bool {
	startHour, startMin, ok1 := parseHHMM(entry.Start)
	endHour, endMin, ok2 := parseHHMM(entry.End)
	if !ok1 || !ok2 || len(entry.Days) == 0 {
		return false
	}
	location := time.UTC
	if entry.Timezone != "" {
		if loaded, err := time.LoadLocation(entry.Timezone); err == nil {
			location = loaded
		}
	}
	local := now.In(location)
	dayNames := map[time.Weekday]string{
		time.Sunday: "sun", time.Monday: "mon", time.Tuesday: "tue",
		time.Wednesday: "wed", time.Thursday: "thu", time.Friday: "fri",
		time.Saturday: "sat",
	}
	listed := func(day time.Weekday) bool {
		name := dayNames[day]
		for _, listedDay := range entry.Days {
			if strings.ToLower(strings.TrimSpace(listedDay)) == name {
				return true
			}
		}
		return false
	}
	minutes := local.Hour()*60 + local.Minute()
	start := startHour*60 + startMin
	end := endHour*60 + endMin
	if start == end {
		return listed(local.Weekday())
	}
	if start < end {
		return listed(local.Weekday()) && minutes >= start && minutes < end
	}
	// Overnight span: late hours on the listed day, or early
	// hours on the day after a listed day.
	if minutes >= start {
		return listed(local.Weekday())
	}
	if minutes < end {
		return listed((local.Weekday() + 6) % 7)
	}
	return false
}

// Track records a new open alert and returns its ID. The ID
// is sequential and stable for the process lifetime.
func Track(title, body, domain string) string {
	mu.Lock()
	defer mu.Unlock()
	counter++
	id := "onc-" + strconv.FormatInt(counter, 10)
	alerts[id] = &OpenAlert{ID: id, Title: title, Body: body, Domain: domain, CreatedAt: time.Now().UTC()}
	// Bound the store: drop acked alerts older than a day.
	for key, alert := range alerts {
		if alert.Acked && time.Since(alert.CreatedAt) > 24*time.Hour {
			delete(alerts, key)
		}
	}
	return id
}

// TrackFixed records or refreshes an alert under a fixed ID
// (used for attack start/end pairs: the end clears the
// start). It returns the ID.
func TrackFixed(id, title, body, domain string) string {
	mu.Lock()
	defer mu.Unlock()
	if existing, ok := alerts[id]; ok && !existing.Acked {
		existing.Title = title
		existing.Body = body
		existing.CreatedAt = time.Now().UTC()
		existing.Escalated = false
		return id
	}
	alerts[id] = &OpenAlert{ID: id, Title: title, Body: body, Domain: domain, CreatedAt: time.Now().UTC()}
	return id
}

// Clear removes a tracked alert (attack end).
func Clear(id string) {
	mu.Lock()
	defer mu.Unlock()
	delete(alerts, id)
}

// Ack marks an alert acknowledged. It reports whether the
// alert existed and was open.
func Ack(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	alert, ok := alerts[id]
	if !ok || alert.Acked {
		return false
	}
	alert.Acked = true
	return true
}

// Open returns a snapshot of the open (unacknowledged)
// alerts, oldest first.
func Open() []OpenAlert {
	mu.Lock()
	defer mu.Unlock()
	out := []OpenAlert{}
	for _, alert := range alerts {
		if !alert.Acked {
			out = append(out, *alert)
		}
	}
	// Oldest first.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.Before(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// DueEscalations returns the open alerts that have waited
// longer than the escalation delay without acknowledgement
// or a previous escalation, and marks them escalated.
func DueEscalations(now time.Time) []OpenAlert {
	mu.Lock()
	defer mu.Unlock()
	delay := time.Duration(cfg.EscalationMinutes) * time.Minute
	if !cfg.Enabled || delay <= 0 {
		return nil
	}
	var due []OpenAlert
	for _, alert := range alerts {
		if alert.Acked || alert.Escalated {
			continue
		}
		if now.Sub(alert.CreatedAt) >= delay {
			alert.Escalated = true
			due = append(due, *alert)
		}
	}
	return due
}
