package intake

import (
	"container/list"
	"crypto/sha256"
	"math"
	"sync"
	"time"
)

// Defaults of the replay and rate guards.
const (
	// DefaultRateBurst and DefaultRatePerSecond: each webhook (project +
	// source) may send a burst of 60 deliveries, then one per second.
	DefaultRateBurst     = 60
	DefaultRatePerSecond = 1.0
	// DefaultReplaySize signatures are remembered for DefaultReplayTTL.
	DefaultReplaySize = 4096
	DefaultReplayTTL  = 10 * time.Minute
	// MaxTimestampSkew is how far Sentry-Hook-Timestamp may be from now.
	MaxTimestampSkew = 5 * time.Minute

	// maxBuckets bounds the limiter's state whatever the configuration
	// does (sources that come and go).
	maxBuckets = 1024
)

// hookKey names a configured webhook.
type hookKey struct{ project, source string }

// limiter is one token bucket per configured webhook. Buckets are made
// only for webhooks the configuration holds, so a caller cannot make
// state by inventing projects or sources.
type limiter struct {
	mu      sync.Mutex
	burst   float64
	rate    float64 // tokens per second
	buckets map[hookKey]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(burst int, perSecond float64) *limiter {
	return &limiter{burst: float64(burst), rate: perSecond, buckets: map[hookKey]*bucket{}}
}

// allow takes one token of k's bucket, or says how long to wait for one.
func (l *limiter) allow(k hookKey, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			// Full buckets hold no information: forget them.
			for k2, b2 := range l.buckets {
				if b2.tokens+now.Sub(b2.last).Seconds()*l.rate >= l.burst {
					delete(l.buckets, k2)
				}
			}
			if len(l.buckets) >= maxBuckets {
				return false, time.Second
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	// A clock that steps back gives no token and is not remembered.
	if d := now.Sub(b.last); d > 0 {
		b.tokens = math.Min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration(math.Ceil((1-b.tokens)/l.rate)) * time.Second
	return false, max(wait, time.Second)
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// replayKey is one accepted delivery: the webhook and the HMAC of its
// body.
type replayKey struct {
	hook hookKey
	mac  [sha256.Size]byte
}

type replayEntry struct {
	key     replayKey
	expires time.Time
}

// replayCache remembers the signatures of the deliveries that were
// accepted lately: at most size of them (the oldest leaves first), each
// for ttl.
type replayCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	seen  map[replayKey]*list.Element
	order *list.List // of replayEntry, oldest first
}

func newReplayCache(size int, ttl time.Duration) *replayCache {
	return &replayCache{max: size, ttl: ttl, seen: map[replayKey]*list.Element{}, order: list.New()}
}

// firstTime records k and reports whether it was not there yet. The check
// and the record are one step: of two identical deliveries that race, one
// is the first.
func (c *replayCache) firstTime(k replayKey, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := c.order.Front(); e != nil; e = c.order.Front() {
		en := e.Value.(replayEntry)
		if en.expires.After(now) {
			break
		}
		c.order.Remove(e)
		delete(c.seen, en.key)
	}
	if _, dup := c.seen[k]; dup {
		return false
	}
	for c.order.Len() >= c.max {
		e := c.order.Front()
		c.order.Remove(e)
		delete(c.seen, e.Value.(replayEntry).key)
	}
	c.seen[k] = c.order.PushBack(replayEntry{key: k, expires: now.Add(c.ttl)})
	return true
}

func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
