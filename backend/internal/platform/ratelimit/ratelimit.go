// Package ratelimit implements GCRA (generic cell rate algorithm) rate
// limiting with a Redis/Valkey backend shared by all API replicas and an
// in-memory backend for tests and single-process use.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule is a sustained rate with a burst allowance.
type Rule struct {
	PerSecond float64
	Burst     int
}

func (r Rule) interval() time.Duration  { return time.Duration(float64(time.Second) / r.PerSecond) }
func (r Rule) tolerance() time.Duration { return r.interval() * time.Duration(r.Burst) }

// Decision is the outcome for one request.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Limiter decides whether a request identified by key may proceed.
type Limiter interface {
	Allow(ctx context.Context, key string, rule Rule) (Decision, error)
}

// gcra is the shared algorithm: tat is the theoretical arrival time.
func gcra(tat, now time.Time, rule Rule) (newTAT time.Time, d Decision) {
	if tat.Before(now) {
		tat = now
	}
	next := tat.Add(rule.interval())
	if diff := next.Sub(now); diff > rule.tolerance() {
		return tat, Decision{RetryAfter: diff - rule.tolerance()}
	}
	return next, Decision{Allowed: true}
}

// Memory is an in-process limiter.
type Memory struct {
	mu  sync.Mutex
	tat map[string]time.Time
	Now func() time.Time
}

// NewMemory returns an empty in-memory limiter.
func NewMemory() *Memory { return &Memory{tat: map[string]time.Time{}, Now: time.Now} }

// Allow implements Limiter.
func (m *Memory) Allow(_ context.Context, key string, rule Rule) (Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	tat, d := gcra(m.tat[key], now, rule)
	if d.Allowed {
		m.tat[key] = tat
	}
	if len(m.tat) > 100_000 { // bound memory: drop expired entries
		for k, v := range m.tat {
			if v.Before(now) {
				delete(m.tat, k)
			}
		}
	}
	return d, nil
}

// gcraScript runs GCRA atomically with the server clock, so replicas with
// skewed clocks agree. Times are microseconds.
var gcraScript = redis.NewScript(`
local key = KEYS[1]
local interval = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local tat = tonumber(redis.call('GET', key) or now)
if tat < now then tat = now end
local nxt = tat + interval
local diff = nxt - now
if diff > tolerance then
  return {0, diff - tolerance}
end
redis.call('SET', key, nxt, 'PX', math.ceil(diff / 1000) + 1)
return {1, 0}
`)

// Redis is a limiter shared across replicas.
type Redis struct {
	R      redis.UniversalClient
	Prefix string
}

// Allow implements Limiter.
func (l *Redis) Allow(ctx context.Context, key string, rule Rule) (Decision, error) {
	res, err := gcraScript.Run(ctx, l.R, []string{l.Prefix + key},
		rule.interval().Microseconds(), rule.tolerance().Microseconds()).Int64Slice()
	if err != nil {
		return Decision{Allowed: true}, err
	}
	if res[0] == 1 {
		return Decision{Allowed: true}, nil
	}
	return Decision{RetryAfter: time.Duration(res[1]) * time.Microsecond}, nil
}

// RetryAfterSeconds rounds up for the Retry-After header (at least 1).
func RetryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}
