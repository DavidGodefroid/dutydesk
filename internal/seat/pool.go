// Package seat is the pool of Claude subscription seats: which seat a pass
// may take, which seats are exhausted, and how their tokens are read.
package seat

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// DefaultExhaustion is how long a seat stays unavailable when the reset time
// of its quota is unknown.
const DefaultExhaustion = time.Hour

// MaxExhaustion is the hard ceiling of the time a seat may be marked
// exhausted, whatever reset time a pass reported: the report comes from the
// output of an untrusted agent container, and a forged one must not take a
// seat out for weeks.
const MaxExhaustion = 24 * time.Hour

// DefaultMaxExhaustion is the ceiling when none is configured.
const DefaultMaxExhaustion = 5 * time.Hour

// StateStore persists the exhaustion of seats across restarts.
type StateStore interface {
	// ExhaustedUntil returns the zero time for a seat that is not exhausted
	// or not known.
	ExhaustedUntil(seat string) (time.Time, error)
	SetExhaustedUntil(seat string, t time.Time) error
}

// Stat is the state of one seat, for `dutydesk seats` and the report.
type Stat struct {
	Name           string
	InUse          int
	MaxParallel    int
	Exhausted      bool
	ExhaustedUntil time.Time // zero when not exhausted
	LastUsed       time.Time // zero when never acquired since start
	ExpiresOn      time.Time // token expiry, zero = unknown
}

type entry struct {
	seat           model.Seat
	inUse          int
	exhaustedUntil time.Time
	lastUsed       time.Time
	lastSeq        uint64 // acquisition order; 0 = never used
}

// Pool is safe for concurrent use.
type Pool struct {
	mu    sync.Mutex
	now   func() time.Time
	store StateStore
	seats []*entry // declaration order
	byNam map[string]*entry
	seq   uint64
	cap   time.Duration // longest exhaustion
}

// WithMaxExhaustion sets the longest time a seat may be marked exhausted
// (default DefaultMaxExhaustion, never above MaxExhaustion).
func WithMaxExhaustion(d time.Duration) Option {
	return func(p *Pool) {
		if d > 0 {
			p.cap = d
		}
	}
}

// Option configures a Pool.
type Option func(*Pool)

// WithClock replaces time.Now (tests).
func WithClock(now func() time.Time) Option {
	return func(p *Pool) { p.now = now }
}

// New builds a pool. store may be nil (exhaustion is then kept in memory
// only). MaxParallel below 1 means 1.
func New(seats []model.Seat, store StateStore, opts ...Option) (*Pool, error) {
	p := &Pool{now: time.Now, store: store, byNam: make(map[string]*entry, len(seats)), cap: DefaultMaxExhaustion}
	for _, o := range opts {
		o(p)
	}
	if p.cap > MaxExhaustion {
		p.cap = MaxExhaustion
	}
	for _, s := range seats {
		if s.Name == "" {
			return nil, errors.New("seat: a seat has no name")
		}
		if _, dup := p.byNam[s.Name]; dup {
			return nil, fmt.Errorf("seat: duplicate seat %q", s.Name)
		}
		if s.MaxParallel < 1 {
			s.MaxParallel = 1
		}
		e := &entry{seat: s}
		if store != nil {
			until, err := store.ExhaustedUntil(s.Name)
			if err != nil {
				return nil, fmt.Errorf("seat %s: read state: %w", s.Name, err)
			}
			// A mark saved before the cap existed (or under a larger cap)
			// is cut down too.
			if limit := p.now().Add(p.cap); until.After(limit) {
				until = limit
			}
			e.exhaustedUntil = until
		}
		p.seats = append(p.seats, e)
		p.byNam[s.Name] = e
	}
	return p, nil
}

// Acquire takes the least recently used seat among the allowed ones (empty =
// all) that is neither exhausted nor at its parallel limit. release must be
// called once the pass is over; calling it again does nothing.
func (p *Pool) Acquire(allowed []string) (model.Seat, func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var best *entry
	for _, e := range p.seats {
		if len(allowed) > 0 && !contains(allowed, e.seat.Name) {
			continue
		}
		if now.Before(e.exhaustedUntil) || e.inUse >= e.seat.MaxParallel {
			continue
		}
		if best == nil || e.lastSeq < best.lastSeq {
			best = e
		}
	}
	if best == nil {
		return model.Seat{}, func() {}, false
	}
	p.seq++
	best.lastSeq = p.seq
	best.lastUsed = now
	best.inUse++
	var once sync.Once
	release := func() {
		once.Do(func() {
			p.mu.Lock()
			best.inUse--
			p.mu.Unlock()
		})
	}
	return best.seat, release, true
}

// MarkExhausted makes a seat unavailable until the given time; a zero time
// (reset unknown) or a time in the past means now + DefaultExhaustion, and
// no mark goes beyond now + the cap (WithMaxExhaustion). The seat is marked
// in memory even when the store fails.
func (p *Pool) MarkExhausted(name string, until time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byNam[name]
	if !ok {
		return fmt.Errorf("seat: unknown seat %q", name)
	}
	now := p.now()
	if !until.After(now) {
		until = now.Add(DefaultExhaustion)
	}
	if limit := now.Add(p.cap); until.After(limit) {
		until = limit
	}
	e.exhaustedUntil = until
	if p.store != nil {
		if err := p.store.SetExhaustedUntil(name, until); err != nil {
			return fmt.Errorf("seat %s: save state: %w", name, err)
		}
	}
	return nil
}

// Token reads the long-lived token of a seat. The file must be a regular
// file owned by the daemon's user with no access for group or others (0600
// or 0400); anything else is refused. The token never appears in errors.
func (p *Pool) Token(name string) (string, error) {
	p.mu.Lock()
	e, ok := p.byNam[name]
	p.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("seat: unknown seat %q", name)
	}
	return ReadTokenFile(e.seat.TokenFile)
}

// maxTokenSize bounds what is read from a token file.
const maxTokenSize = 16 << 10

// ReadTokenFile reads one token file with the checks described on Pool.Token.
func ReadTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("seat: no token file configured")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("seat: token file: %w", err)
	}
	defer f.Close()
	// Checks are made on the open file, not on the path: no race with a swap.
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("seat: token file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("seat: token file %s is not a regular file", path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("seat: token file %s has mode %04o; it must be 0600 or 0400", path, perm)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return "", fmt.Errorf("seat: token file %s is not owned by the user running dutydesk", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenSize+1))
	if err != nil {
		return "", fmt.Errorf("seat: token file: %w", err)
	}
	if len(data) > maxTokenSize {
		return "", fmt.Errorf("seat: token file %s is too large", path)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("seat: token file %s is empty", path)
	}
	if strings.ContainsAny(token, " \t\r\n\x00") {
		return "", fmt.Errorf("seat: token file %s must hold a single token", path)
	}
	return token, nil
}

// Expiring lists the seats whose token expires within the given duration,
// already expired ones included. Seats with an unknown expiry are left out.
func (p *Pool) Expiring(within time.Duration) []model.Seat {
	p.mu.Lock()
	defer p.mu.Unlock()
	limit := p.now().Add(within)
	var out []model.Seat
	for _, e := range p.seats {
		if !e.seat.ExpiresOn.IsZero() && !e.seat.ExpiresOn.After(limit) {
			out = append(out, e.seat)
		}
	}
	return out
}

// Stats returns the state of every seat, in declaration order.
func (p *Pool) Stats() []Stat {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]Stat, 0, len(p.seats))
	for _, e := range p.seats {
		s := Stat{
			Name: e.seat.Name, InUse: e.inUse, MaxParallel: e.seat.MaxParallel,
			LastUsed: e.lastUsed, ExpiresOn: e.seat.ExpiresOn,
		}
		if now.Before(e.exhaustedUntil) {
			s.Exhausted = true
			s.ExhaustedUntil = e.exhaustedUntil
		}
		out = append(out, s)
	}
	return out
}

// AllExhausted reports whether every seat of the pool is out of quota.
func (p *Pool) AllExhausted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for _, e := range p.seats {
		if !now.Before(e.exhaustedUntil) {
			return false
		}
	}
	return len(p.seats) > 0
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
