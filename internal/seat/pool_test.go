package seat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type memStore struct {
	mu      sync.Mutex
	m       map[string]time.Time
	failSet error
	failGet error
}

func (s *memStore) ExhaustedUntil(seat string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[seat], s.failGet
}

func (s *memStore) SetExhaustedUntil(seat string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSet != nil {
		return s.failSet
	}
	if s.m == nil {
		s.m = map[string]time.Time{}
	}
	s.m[seat] = t
	return nil
}

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func newPool(t *testing.T, store StateStore, seats ...model.Seat) (*Pool, *clock) {
	t.Helper()
	c := &clock{t: t0}
	p, err := New(seats, store, WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	return p, c
}

func acquire(t *testing.T, p *Pool, allowed ...string) (string, func()) {
	t.Helper()
	s, rel, ok := p.Acquire(allowed)
	if !ok {
		t.Fatalf("no seat available (allowed=%v)", allowed)
	}
	return s.Name, rel
}

func TestNewRejectsBadSeats(t *testing.T) {
	if _, err := New([]model.Seat{{Name: ""}}, nil); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := New([]model.Seat{{Name: "a"}, {Name: "a"}}, nil); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := New([]model.Seat{{Name: "a"}}, &memStore{failGet: errors.New("db down")}); err == nil {
		t.Error("store failure ignored")
	}
}

func TestAcquireLeastRecentlyUsed(t *testing.T) {
	p, _ := newPool(t, nil, model.Seat{Name: "a"}, model.Seat{Name: "b"}, model.Seat{Name: "c"})
	// Never used: declaration order.
	var got []string
	var rels []func()
	for i := 0; i < 3; i++ {
		n, rel := acquire(t, p)
		got = append(got, n)
		rels = append(rels, rel)
	}
	if strings.Join(got, "") != "abc" {
		t.Fatalf("first round = %v", got)
	}
	if _, _, ok := p.Acquire(nil); ok {
		t.Fatal("a fourth pass got a seat (MaxParallel defaults to 1)")
	}
	// Release in another order: the choice follows acquisition time, not release time.
	rels[2]()
	rels[0]()
	rels[1]()
	if n, rel := acquire(t, p); n != "a" {
		t.Fatalf("got %s, want a (least recently used)", n)
	} else {
		rel()
	}
	if n, _ := acquire(t, p); n != "b" {
		t.Fatalf("got %s, want b", n)
	}
	if n, _ := acquire(t, p); n != "c" {
		t.Fatalf("got %s, want c", n)
	}
}

func TestAcquireAllowedList(t *testing.T) {
	p, _ := newPool(t, nil, model.Seat{Name: "a"}, model.Seat{Name: "b"})
	n, rel := acquire(t, p, "b")
	if n != "b" {
		t.Fatalf("got %s", n)
	}
	if _, _, ok := p.Acquire([]string{"b"}); ok {
		t.Fatal("b given twice")
	}
	if _, _, ok := p.Acquire([]string{"zzz"}); ok {
		t.Fatal("unknown seat given")
	}
	rel()
	if n, _ := acquire(t, p, "b", "zzz"); n != "b" {
		t.Fatalf("got %s", n)
	}
}

func TestMaxParallelAndRelease(t *testing.T) {
	p, _ := newPool(t, nil, model.Seat{Name: "a", MaxParallel: 2})
	_, rel1 := acquire(t, p)
	_, rel2 := acquire(t, p)
	if _, _, ok := p.Acquire(nil); ok {
		t.Fatal("third parallel pass accepted")
	}
	rel1()
	rel1() // idempotent: must not free a second slot
	if st := p.Stats()[0]; st.InUse != 1 || st.MaxParallel != 2 {
		t.Fatalf("stats = %+v", st)
	}
	_, rel3 := acquire(t, p)
	if _, _, ok := p.Acquire(nil); ok {
		t.Fatal("double release freed two slots")
	}
	rel2()
	rel3()
	if st := p.Stats()[0]; st.InUse != 0 {
		t.Fatalf("in use = %d", st.InUse)
	}
	// The release func of a failed Acquire is callable.
	p2, _ := newPool(t, nil)
	_, rel, ok := p2.Acquire(nil)
	if ok {
		t.Fatal("empty pool gave a seat")
	}
	rel()
}

func TestMarkExhausted(t *testing.T) {
	store := &memStore{}
	p, c := newPool(t, store, model.Seat{Name: "a"}, model.Seat{Name: "b"})

	if err := p.MarkExhausted("nope", time.Time{}); err == nil {
		t.Error("unknown seat accepted")
	}
	// Known reset time.
	until := t0.Add(3 * time.Hour)
	if err := p.MarkExhausted("a", until); err != nil {
		t.Fatal(err)
	}
	if !store.m["a"].Equal(until) {
		t.Errorf("store = %v", store.m["a"])
	}
	// Unknown reset time: one hour.
	if err := p.MarkExhausted("b", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !store.m["b"].Equal(t0.Add(time.Hour)) {
		t.Errorf("store = %v", store.m["b"])
	}
	if _, _, ok := p.Acquire(nil); ok {
		t.Fatal("an exhausted seat was given")
	}
	st := p.Stats()
	if !st[0].Exhausted || !st[0].ExhaustedUntil.Equal(until) || !st[1].Exhausted {
		t.Fatalf("stats = %+v", st)
	}

	c.Advance(time.Hour) // b is back exactly at its reset time
	if n, rel := acquire(t, p); n != "b" {
		t.Fatalf("got %s", n)
	} else {
		rel()
	}
	if _, _, ok := p.Acquire([]string{"a"}); ok {
		t.Fatal("a given before its reset")
	}
	c.Advance(2 * time.Hour)
	if n, _ := acquire(t, p, "a"); n != "a" {
		t.Fatalf("got %s", n)
	}
	if st := p.Stats()[0]; st.Exhausted || !st.ExhaustedUntil.IsZero() {
		t.Fatalf("stats = %+v", st)
	}

	// A reset time in the past is treated as unknown.
	if err := p.MarkExhausted("b", t0); err != nil {
		t.Fatal(err)
	}
	if want := c.Now().Add(time.Hour); !store.m["b"].Equal(want) {
		t.Errorf("store = %v, want %v", store.m["b"], want)
	}
}

func TestExhaustionSurvivesRestart(t *testing.T) {
	store := &memStore{m: map[string]time.Time{"a": t0.Add(30 * time.Minute)}}
	p, c := newPool(t, store, model.Seat{Name: "a"}, model.Seat{Name: "b"})
	if n, _ := acquire(t, p); n != "b" {
		t.Fatalf("got %s, want b (a is exhausted in the store)", n)
	}
	c.Advance(31 * time.Minute)
	if n, _ := acquire(t, p); n != "a" {
		t.Fatalf("got %s", n)
	}
}

func TestMarkExhaustedStoreFailure(t *testing.T) {
	p, _ := newPool(t, &memStore{failSet: errors.New("disk full")}, model.Seat{Name: "a"})
	if err := p.MarkExhausted("a", time.Time{}); err == nil {
		t.Fatal("store error swallowed")
	}
	if _, _, ok := p.Acquire(nil); ok {
		t.Fatal("seat must stay exhausted in memory when the store fails")
	}
}

func TestToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const tok = "sk-ant-oat01-abcDEF_123"
	link := filepath.Join(dir, "link")
	good := write("good", tok+"\n", 0o600)
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	p, _ := newPool(t, nil,
		model.Seat{Name: "good", TokenFile: good},
		model.Seat{Name: "ro", TokenFile: write("ro", tok, 0o400)},
		model.Seat{Name: "group", TokenFile: write("group", tok, 0o640)},
		model.Seat{Name: "world", TokenFile: write("world", tok, 0o604)},
		model.Seat{Name: "empty", TokenFile: write("empty", " \n", 0o600)},
		model.Seat{Name: "two", TokenFile: write("two", tok+"\nOTHER=1\n", 0o600)},
		model.Seat{Name: "missing", TokenFile: filepath.Join(dir, "absent")},
		model.Seat{Name: "dir", TokenFile: dir},
		model.Seat{Name: "nofile"},
		model.Seat{Name: "link", TokenFile: link},
	)
	for _, name := range []string{"good", "ro", "link"} {
		got, err := p.Token(name)
		if err != nil || got != tok {
			t.Errorf("%s: token = %q, err = %v", name, got, err)
		}
	}
	for _, name := range []string{"group", "world", "empty", "two", "missing", "dir", "nofile", "unknown"} {
		got, err := p.Token(name)
		if err == nil || got != "" {
			t.Errorf("%s: accepted (token %q)", name, got)
			continue
		}
		if strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error leaks the token: %v", name, err)
		}
	}
	if _, err := p.Token("group"); !strings.Contains(err.Error(), "0640") {
		t.Errorf("mode error = %v", err)
	}
}

func TestExpiring(t *testing.T) {
	p, c := newPool(t, nil,
		model.Seat{Name: "soon", ExpiresOn: t0.Add(10 * 24 * time.Hour)},
		model.Seat{Name: "later", ExpiresOn: t0.Add(90 * 24 * time.Hour)},
		model.Seat{Name: "expired", ExpiresOn: t0.Add(-time.Hour)},
		model.Seat{Name: "unknown"},
	)
	names := func(seats []model.Seat) string {
		var n []string
		for _, s := range seats {
			n = append(n, s.Name)
		}
		return strings.Join(n, ",")
	}
	if got := names(p.Expiring(30 * 24 * time.Hour)); got != "soon,expired" {
		t.Errorf("expiring = %s", got)
	}
	c.Advance(61 * 24 * time.Hour)
	if got := names(p.Expiring(30 * 24 * time.Hour)); got != "soon,later,expired" {
		t.Errorf("expiring = %s", got)
	}
}

func TestStats(t *testing.T) {
	exp := t0.Add(48 * time.Hour)
	p, c := newPool(t, nil, model.Seat{Name: "a", ExpiresOn: exp}, model.Seat{Name: "b", MaxParallel: 3})
	c.Advance(time.Minute)
	_, _ = acquire(t, p)
	st := p.Stats()
	if len(st) != 2 || st[0].Name != "a" || st[0].InUse != 1 || st[0].MaxParallel != 1 ||
		!st[0].LastUsed.Equal(t0.Add(time.Minute)) || !st[0].ExpiresOn.Equal(exp) {
		t.Fatalf("stats[0] = %+v", st[0])
	}
	if st[1].InUse != 0 || st[1].MaxParallel != 3 || !st[1].LastUsed.IsZero() || st[1].Exhausted {
		t.Fatalf("stats[1] = %+v", st[1])
	}
}

func TestConcurrentUse(t *testing.T) {
	store := &memStore{}
	p, c := newPool(t, store,
		model.Seat{Name: "a", MaxParallel: 2}, model.Seat{Name: "b"}, model.Seat{Name: "c", MaxParallel: 3})
	limits := map[string]int{"a": 2, "b": 1, "c": 3}
	var mu sync.Mutex
	held := map[string]int{}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				s, rel, ok := p.Acquire(nil)
				if ok {
					mu.Lock()
					held[s.Name]++
					if held[s.Name] > limits[s.Name] {
						t.Errorf("seat %s held %d times", s.Name, held[s.Name])
					}
					mu.Unlock()
					mu.Lock()
					held[s.Name]--
					mu.Unlock()
					rel()
				}
				switch i % 50 {
				case 7:
					_ = p.MarkExhausted("b", c.Now().Add(time.Millisecond))
				case 9:
					c.Advance(time.Millisecond)
				case 11:
					_ = p.Stats()
					_ = p.Expiring(time.Hour)
				}
			}
		}(g)
	}
	wg.Wait()
	for _, st := range p.Stats() {
		if st.InUse != 0 {
			t.Errorf("seat %s still in use: %d", st.Name, st.InUse)
		}
	}
}
