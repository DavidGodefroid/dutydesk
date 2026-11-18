package notify

import (
	"context"
	"io"
	"net/http"
	"time"
)

// Heartbeat pings a dead-man switch while DutyDesk is healthy: the receiving
// side raises the alarm when the pings stop. The URL is a secret and is never
// logged.
type Heartbeat struct {
	URL      string        // Alerts.HeartbeatURL or the daemon-level URL; "" = off
	Interval time.Duration // default 1 min
	Healthy  func() bool   // nil = always healthy
	Client   *http.Client  // default: 10 s timeout
	// Logf, when set, is told about failed pings (never the URL).
	Logf func(format string, args ...any)
}

// Start launches the goroutine: one ping at once, then one per interval,
// skipped whenever Healthy returns false. It stops when ctx is cancelled; the
// returned channel is closed once it has stopped.
func (h *Heartbeat) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if h.URL == "" {
		close(done)
		return done
	}
	interval := h.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			h.beat(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (h *Heartbeat) beat(ctx context.Context) {
	if ctx.Err() != nil || (h.Healthy != nil && !h.Healthy()) {
		return
	}
	client := h.Client
	if client == nil {
		client = defaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		h.logf("notify: heartbeat URL is invalid")
		return
	}
	req.Header.Set("User-Agent", "dutydesk")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			h.logf("notify: heartbeat failed: %s", scrub(err, h.URL))
		}
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode > 299 {
		h.logf("notify: heartbeat answered HTTP %d", resp.StatusCode)
	}
}

func (h *Heartbeat) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}
