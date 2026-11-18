package domains

// Cron schedules for firewall rules (Batch 7).
//
// A schedule is a 5-field cron expression — minute, hour,
// day-of-month, month, day-of-week — in the domain's
// scheduleTimezone (default UTC). Each field accepts "*",
// lists ("1,15"), ranges ("9-17"), steps ("*/15",
// "9-17/2"), and combinations ("1,15,30-45/5"). Day-of-week
// uses 0-6 with Sunday as 0; 7 is also accepted as Sunday.
// Month and weekday NAMES are not supported: numbers only.
//
// Day-of-month / day-of-week semantics follow Vixie cron:
// when both fields are restricted (not "*"), a time matches
// when EITHER matches; when only one is restricted, that one
// decides. A rule with no schedule is always active.
//
// An invalid schedule never disables a rule: the load path
// warns and treats the rule as always active (fail safe),
// while the API rejects invalid schedules at write time so
// bad expressions cannot enter through the control panel.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed cron expression. The zero value is
// not usable; always build one with ParseSchedule.
type Schedule struct {
	minutes [60]bool
	hours   [24]bool
	dom     [32]bool // index 1..31
	months  [13]bool // index 1..12
	dow     [7]bool  // index 0..6, Sunday = 0

	domRestricted bool
	dowRestricted bool

	// Expression is the original text, for reporting.
	Expression string
}

// ParseSchedule parses a 5-field cron expression.
func ParseSchedule(expr string) (*Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("schedule must have 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	schedule := &Schedule{Expression: expr}
	minuteSet, err := parseCronField(fields[0], 0, 59, "minute")
	if err != nil {
		return nil, err
	}
	for value := 0; value <= 59; value++ {
		schedule.minutes[value] = minuteSet[value]
	}
	hourSet, err := parseCronField(fields[1], 0, 23, "hour")
	if err != nil {
		return nil, err
	}
	for value := 0; value <= 23; value++ {
		schedule.hours[value] = hourSet[value]
	}
	domSet, err := parseCronField(fields[2], 1, 31, "day-of-month")
	if err != nil {
		return nil, err
	}
	// parseCronField indexes from 0 (value-min); re-map
	// day-of-month into the 1-based array.
	schedule.dom = [32]bool{}
	for value := 1; value <= 31; value++ {
		schedule.dom[value] = domSet[value-1]
	}
	monthSet, err := parseCronField(fields[3], 1, 12, "month")
	if err != nil {
		return nil, err
	}
	schedule.months = [13]bool{}
	for value := 1; value <= 12; value++ {
		schedule.months[value] = monthSet[value-1]
	}
	dowSet, err := parseCronField(fields[4], 0, 7, "day-of-week")
	if err != nil {
		return nil, err
	}
	for value := 0; value <= 6; value++ {
		schedule.dow[value] = dowSet[value]
	}
	if dowSet[7] {
		schedule.dow[0] = true // 7 is Sunday too.
	}

	schedule.domRestricted = !allSet(schedule.dom[1:])
	schedule.dowRestricted = !allSet(schedule.dow[:])
	return schedule, nil
}

// ValidateSchedule reports whether expr is a usable schedule
// string. Empty means "no schedule" and is valid.
func ValidateSchedule(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	_, err := ParseSchedule(expr)
	return err
}

// ActiveAt reports whether the schedule matches t. The
// caller converts t to the domain's timezone first.
func (s *Schedule) ActiveAt(t time.Time) bool {
	if s == nil {
		return true
	}
	if !s.minutes[t.Minute()] || !s.hours[t.Hour()] || !s.months[int(t.Month())] {
		return false
	}
	domMatch := s.dom[t.Day()]
	dowMatch := s.dow[int(t.Weekday())]
	switch {
	case s.domRestricted && s.dowRestricted:
		return domMatch || dowMatch
	case s.domRestricted:
		return domMatch
	case s.dowRestricted:
		return dowMatch
	default:
		return true
	}
}

// parseCronField parses one cron field into a boolean set
// indexed from 0 (value-min). Ranges are inclusive.
func parseCronField(field string, min, max int, name string) ([64]bool, error) {
	var set [64]bool
	if field == "" {
		return set, fmt.Errorf("empty %s field", name)
	}
	for _, item := range strings.Split(field, ",") {
		if item == "" {
			return set, fmt.Errorf("empty item in %s field", name)
		}
		step := 1
		base := item
		if slash := strings.Index(item, "/"); slash >= 0 {
			base = item[:slash]
			parsed, err := strconv.Atoi(item[slash+1:])
			if err != nil || parsed <= 0 {
				return set, fmt.Errorf("invalid step in %s field %q", name, item)
			}
			step = parsed
		}
		lo, hi := min, max
		switch {
		case base == "*":
			// Whole range.
		case strings.Contains(base, "-"):
			parts := strings.SplitN(base, "-", 2)
			var err error
			if lo, err = parseCronValue(parts[0], min, max, name); err != nil {
				return set, err
			}
			if hi, err = parseCronValue(parts[1], min, max, name); err != nil {
				return set, err
			}
			if lo > hi {
				return set, fmt.Errorf("reversed range %q in %s field", base, name)
			}
		default:
			value, err := parseCronValue(base, min, max, name)
			if err != nil {
				return set, err
			}
			lo, hi = value, value
			// "N/step" means N..max/step, per cron
			// convention; a bare "N" (step 1, lo==hi)
			// sets just N.
			if strings.Contains(item, "/") {
				hi = max
			}
		}
		for value := lo; value <= hi; value += step {
			set[value-min] = true
		}
	}
	return set, nil
}

func parseCronValue(text string, min, max int, name string) (int, error) {
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: not a number", name, text)
	}
	if value < min || value > max {
		return 0, fmt.Errorf("%s value %d out of range %d-%d", name, value, min, max)
	}
	return value, nil
}

func allSet(values []bool) bool {
	for _, set := range values {
		if !set {
			return false
		}
	}
	return true
}

// ParseScheduleTimezone resolves an IANA timezone name. An
// empty name means UTC. The caller warns and falls back to
// UTC when an error is returned.
func ParseScheduleTimezone(name string) (*time.Location, error) {
	if strings.TrimSpace(name) == "" {
		return time.UTC, nil
	}
	return time.LoadLocation(name)
}

// ParseMaintenanceWindows validates scheduled maintenance
// windows, returning the usable ones plus one warning per
// dropped window. A window is dropped when either timestamp
// fails to parse as RFC 3339 or the end is not after the
// start. Dropping is fail-safe: no maintenance is served
// for a window the proxy cannot interpret.
func ParseMaintenanceWindows(windows []MaintenanceWindow) ([]ParsedMaintenanceWindow, []string) {
	parsed := []ParsedMaintenanceWindow{}
	warnings := []string{}
	for i, window := range windows {
		start, err := time.Parse(time.RFC3339, window.Start)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("maintenance window %d: invalid start %q", i, window.Start))
			continue
		}
		end, err := time.Parse(time.RFC3339, window.End)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("maintenance window %d: invalid end %q", i, window.End))
			continue
		}
		if !end.After(start) {
			warnings = append(warnings, fmt.Sprintf("maintenance window %d: end is not after start", i))
			continue
		}
		parsed = append(parsed, ParsedMaintenanceWindow{Start: start, End: end, Message: window.Message})
	}
	return parsed, warnings
}

// MaintenanceActiveAt reports whether any parsed window
// covers t, and the first covering window's message.
func MaintenanceActiveAt(windows []ParsedMaintenanceWindow, t time.Time) (bool, string) {
	for _, window := range windows {
		if !t.Before(window.Start) && t.Before(window.End) {
			return true, window.Message
		}
	}
	return false, ""
}
