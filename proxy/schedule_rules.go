package proxy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ScheduleWindow struct {
	Profile string
	Days    []string
	Start   string
	End     string
}

type ScheduleRules struct {
	byProfile map[string][]scheduleWindow
}

type scheduleWindow struct {
	days  [7]bool
	start int
	end   int
}

func NewScheduleRules(windows []ScheduleWindow) (*ScheduleRules, error) {
	rules := &ScheduleRules{byProfile: make(map[string][]scheduleWindow)}
	for _, window := range windows {
		if window.Profile == "" {
			return nil, fmt.Errorf("schedule profile cannot be empty")
		}
		compiled, err := compileScheduleWindow(window)
		if err != nil {
			return nil, fmt.Errorf("schedule profile %s: %w", window.Profile, err)
		}
		rules.byProfile[window.Profile] = append(rules.byProfile[window.Profile], compiled)
	}
	return rules, nil
}

func (r *ScheduleRules) Allowed(profile string, now time.Time) bool {
	if r == nil {
		return true
	}
	windows := r.byProfile[profile]
	if len(windows) == 0 {
		return true
	}
	day := now.Weekday()
	minute := now.Hour()*60 + now.Minute()
	for _, window := range windows {
		if !window.days[day] {
			continue
		}
		if window.start <= minute && minute < window.end {
			return true
		}
	}
	return false
}

func compileScheduleWindow(window ScheduleWindow) (scheduleWindow, error) {
	var out scheduleWindow
	if len(window.Days) == 0 {
		for i := range out.days {
			out.days[i] = true
		}
	} else {
		for _, day := range window.Days {
			weekday, err := parseWeekday(day)
			if err != nil {
				return out, err
			}
			out.days[weekday] = true
		}
	}
	start, err := parseClockMinute(window.Start)
	if err != nil {
		return out, fmt.Errorf("start: %w", err)
	}
	end, err := parseClockMinute(window.End)
	if err != nil {
		return out, fmt.Errorf("end: %w", err)
	}
	if end <= start {
		return out, fmt.Errorf("end must be after start")
	}
	out.start = start
	out.end = end
	return out, nil
}

func parseWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	}
	return 0, fmt.Errorf("invalid weekday %q", value)
}

func parseClockMinute(value string) (int, error) {
	hourText, minuteText, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return 0, fmt.Errorf("invalid clock %q", value)
	}
	hour, err := strconv.Atoi(hourText)
	if err != nil {
		return 0, err
	}
	minute, err := strconv.Atoi(minuteText)
	if err != nil {
		return 0, err
	}
	if hour == 24 && minute == 0 {
		return 24 * 60, nil
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid clock %q", value)
	}
	return hour*60 + minute, nil
}
