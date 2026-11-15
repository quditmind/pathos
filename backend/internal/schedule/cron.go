// Package schedule implements scan schedules: a cron parser, the schedule
// API and the leader-elected scheduler loop.
package schedule

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cron is a parsed five-field cron expression (minute hour day-of-month
// month day-of-week) evaluated in a time zone.
type Cron struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
	expr                          string
}

var macros = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

var monthNames = map[string]int{"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
var dowNames = map[string]int{"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}

// ParseCron parses a standard five-field expression or a macro (@daily ...).
func ParseCron(expr string) (*Cron, error) {
	expr = strings.TrimSpace(expr)
	src := expr
	if m, ok := macros[strings.ToLower(expr)]; ok {
		src = m
	}
	f := strings.Fields(src)
	if len(f) != 5 {
		return nil, errors.New("cron expression needs five fields: minute hour day-of-month month day-of-week")
	}
	c := &Cron{expr: expr}
	var err error
	if c.minute, _, err = field(f[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if c.hour, _, err = field(f[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if c.dom, c.domStar, err = field(f[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	if c.month, _, err = field(f[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if c.dow, c.dowStar, err = field(f[4], 0, 7, dowNames); err != nil {
		return nil, fmt.Errorf("day of week: %w", err)
	}
	if c.dow&(1<<7) != 0 { // 7 is Sunday too
		c.dow |= 1
		c.dow &^= 1 << 7
	}
	return c, nil
}

func field(s string, lo, hi int, names map[string]int) (uint64, bool, error) {
	var bits uint64
	star := s == "*" || s == "?"
	for _, part := range strings.Split(s, ",") {
		step := 1
		if i := strings.IndexByte(part, '/'); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 || n > hi {
				return 0, false, fmt.Errorf("invalid step %q", part[i+1:])
			}
			step, part = n, part[:i]
		}
		a, b := lo, hi
		switch {
		case part == "*" || part == "?":
		case strings.Contains(part, "-"):
			x, y, _ := strings.Cut(part, "-")
			var err error
			if a, err = value(x, lo, hi, names); err != nil {
				return 0, false, err
			}
			if b, err = value(y, lo, hi, names); err != nil {
				return 0, false, err
			}
			if a > b {
				return 0, false, fmt.Errorf("range %q is reversed", part)
			}
		default:
			v, err := value(part, lo, hi, names)
			if err != nil {
				return 0, false, err
			}
			a, b = v, v
			if step > 1 { // "5/15" means from 5 to the end
				b = hi
			}
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	if bits == 0 {
		return 0, false, errors.New("matches nothing")
	}
	return bits, star, nil
}

func value(s string, lo, hi int, names map[string]int) (int, error) {
	if v, ok := names[strings.ToUpper(s)]; ok {
		return v, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < lo || v > hi {
		return 0, fmt.Errorf("value %q out of range %d-%d", s, lo, hi)
	}
	return v, nil
}

func (c *Cron) String() string { return c.expr }

func (c *Cron) dayMatches(t time.Time) bool {
	d := c.dom&(1<<uint(t.Day())) != 0
	w := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return w
	case c.dowStar:
		return d
	default: // both restricted: standard cron ORs them
		return d || w
	}
}

// Next returns the first activation strictly after t, in loc. It returns the
// zero time if there is none within five years (e.g. "0 0 31 2 *").
func (c *Cron) Next(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc).Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if c.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
			continue
		}
		if !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			continue
		}
		if c.hour&(1<<uint(t.Hour())) == 0 {
			want := t.Hour() + 1
			next := time.Date(t.Year(), t.Month(), t.Day(), want, 0, 0, 0, loc)
			if !next.After(t) { // DST fall-back repeats an hour
				next = t.Add(time.Hour).Truncate(time.Hour)
			}
			if want < 24 && next.Hour() != want && next.Day() == t.Day() && c.hour&(1<<uint(want)) != 0 {
				// Spring-forward skipped the wanted hour: run right after the
				// jump instead of skipping the day (as vixie cron does).
				for m := 0; m < 60; m++ {
					if c.minute&(1<<uint(m)) != 0 {
						return next.Add(time.Duration(m) * time.Minute)
					}
				}
			}
			t = next
			continue
		}
		if c.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// MinInterval returns the shortest gap between the next n activations after
// from. Used to reject schedules that would scan too often.
func (c *Cron) MinInterval(from time.Time, loc *time.Location, n int) time.Duration {
	prev := c.Next(from, loc)
	if prev.IsZero() {
		return 0
	}
	min := time.Duration(1<<63 - 1)
	for range n {
		next := c.Next(prev, loc)
		if next.IsZero() {
			break
		}
		if d := next.Sub(prev); d < min {
			min = d
		}
		prev = next
	}
	return min
}
