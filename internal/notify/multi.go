package notify

import (
	"context"
	"errors"
	"sync"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Multi sends every alert to all its notifiers and joins their errors.
type Multi []model.Notifier

var _ model.Notifier = Multi(nil)

func (m Multi) Send(ctx context.Context, p *model.Project, a model.Alert) error {
	var errs []error
	for _, n := range m {
		if n == nil {
			continue
		}
		if err := n.Send(ctx, p, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Sent is one alert kept by a Recorder.
type Sent struct {
	Project string // slug, "" when sent without a project
	Alert   model.Alert
}

// Recorder is a Notifier for tests: it keeps what it was asked to send.
type Recorder struct {
	Err error // returned by Send when set (the alert is still recorded)

	mu   sync.Mutex
	sent []Sent
}

var _ model.Notifier = (*Recorder)(nil)

func (r *Recorder) Send(_ context.Context, p *model.Project, a model.Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Sent{Alert: a}
	if p != nil {
		s.Project = p.Slug
	}
	r.sent = append(r.sent, s)
	return r.Err
}

// Sent returns a copy of the recorded alerts, oldest first.
func (r *Recorder) Sent() []Sent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Sent(nil), r.sent...)
}

// Kinds returns the kinds of the recorded alerts, oldest first.
func (r *Recorder) Kinds() []model.AlertKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.AlertKind, len(r.sent))
	for i, s := range r.sent {
		out[i] = s.Alert.Kind
	}
	return out
}

// Reset forgets the recorded alerts.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = nil
}
