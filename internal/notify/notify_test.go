package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func project(t *testing.T, url string) *model.Project {
	t.Helper()
	file := filepath.Join(t.TempDir(), "webhook-url")
	if err := os.WriteFile(file, []byte(url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &model.Project{Slug: "shop", Alerts: model.AlertConfig{WebhookURLFile: file}}
}

var fast = []time.Duration{time.Millisecond}

func TestFormat(t *testing.T) {
	title, text := Format(model.Alert{Kind: model.AlertEscalated, Project: "shop", Incident: "INC-000123",
		Title: "Orders stuck\nin queue", Body: "Three passes without a fix.\nPlease look at the worker.", URL: "https://example.com/t/1"})
	if title != "[DutyDesk] Escalated · shop · INC-000123: Orders stuck in queue" {
		t.Errorf("title %q", title)
	}
	if text != "Three passes without a fix.\nPlease look at the worker.\nhttps://example.com/t/1" {
		t.Errorf("text %q", text)
	}

	_, text = Format(model.Alert{Kind: model.AlertGreenLight, Project: "shop", Incident: "INC-1", Title: "Restart worker", Body: "The agent asks to restart the worker."})
	if !strings.Contains(text, "paired phone") || !strings.Contains(text, "`lox approve`") {
		t.Errorf("green light text does not say where to answer: %q", text)
	}
	if _, other := Format(model.Alert{Kind: model.AlertEscalated, Body: "x"}); strings.Contains(other, "lox approve") {
		t.Errorf("hint on a non green-light alert: %q", other)
	}

	title, text = Format(model.Alert{Kind: model.AlertCapacity, Title: "No seat left"})
	if title != "[DutyDesk] Capacity exhausted: No seat left" || text != "" {
		t.Errorf("system alert: %q / %q", title, text)
	}

	_, text = Format(model.Alert{Kind: model.AlertStorm, Body: strings.Repeat("é", 2000), URL: "https://example.com/x"})
	body, _, _ := strings.Cut(text, "\n")
	if n := len([]rune(body)); n != maxBody || !strings.HasSuffix(body, "…") {
		t.Errorf("body of %d characters", n)
	}
	if !strings.HasSuffix(text, "https://example.com/x") {
		t.Error("URL lost after truncation")
	}
	for kind := range kindLabels {
		if l := KindLabel(kind); l == "" || l == string(kind) {
			t.Errorf("kind %q has no label", kind)
		}
	}
	if KindLabel("custom") != "custom" {
		t.Error("unknown kind")
	}
}

func TestWebhookPayload(t *testing.T) {
	var got map[string]any
	var contentType, method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, contentType = r.Method, r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	a := model.Alert{Kind: model.AlertGreenLight, Project: "shop", Incident: "INC-000123", Title: "Restart worker",
		Body: strings.Repeat("long body ", 200), URL: "https://example.com/ticket/9", At: time.Date(2026, 11, 18, 10, 30, 0, 0, time.UTC)}
	if err := (&Webhook{}).Send(context.Background(), project(t, srv.URL+"/hook/secret-path"), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if method != "POST" || contentType != "application/json" {
		t.Fatalf("%s %s", method, contentType)
	}
	if got["type"] != "message" {
		t.Fatalf("type %v", got["type"])
	}
	title, text := Format(a)
	if got["text"] != title+"\n"+text {
		t.Errorf("fallback text %q", got["text"])
	}
	att := got["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("attachment %v", att)
	}
	card := att["content"].(map[string]any)
	if card["type"] != "AdaptiveCard" || card["version"] == nil || card["$schema"] == nil {
		t.Fatalf("card %v", card)
	}
	raw, _ := json.Marshal(card)
	for _, want := range []string{"Green light needed", "shop", "INC-000123", "Restart worker", "lox approve", "Action.OpenUrl", "https://example.com/ticket/9"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("card lacks %q", want)
		}
	}
	if len(raw) > 2500 {
		t.Errorf("card of %d bytes: the body was not truncated", len(raw))
	}
}

func TestWebhookRetriesOn5xxThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	if err := (&Webhook{Backoff: fast}).Send(context.Background(), project(t, srv.URL), model.Alert{Kind: model.AlertStorm}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n.Load() != 3 {
		t.Fatalf("%d attempts, want 3", n.Load())
	}
}

func TestWebhookGivesUpAfterThreeAttempts(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	err := (&Webhook{Backoff: fast}).Send(context.Background(), project(t, srv.URL+"/hook/secret-path"), model.Alert{Kind: model.AlertStorm})
	if err == nil || !strings.Contains(err.Error(), "503") || n.Load() != 3 {
		t.Fatalf("err %v after %d attempts", err, n.Load())
	}
	if strings.Contains(err.Error(), "secret-path") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("error holds the URL: %v", err)
	}
}

func TestWebhook4xxIsFinal(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	err := (&Webhook{Backoff: fast}).Send(context.Background(), project(t, srv.URL), model.Alert{Kind: model.AlertStorm})
	if err == nil || !strings.Contains(err.Error(), "400") || n.Load() != 1 {
		t.Fatalf("err %v after %d attempts", err, n.Load())
	}
}

func TestWebhookNetworkErrorIsRetriedAndHidesTheURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/hook/secret-path?sig=abcdef"
	srv.Close() // nothing listens any more
	start := time.Now()
	err := (&Webhook{Backoff: []time.Duration{20 * time.Millisecond}}).Send(context.Background(), project(t, url), model.Alert{Kind: model.AlertStorm})
	if err == nil {
		t.Fatal("no error")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("no retry: returned after %v", time.Since(start))
	}
	for _, leak := range []string{"secret-path", "abcdef", srv.URL} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error holds %q: %v", leak, err)
		}
	}
}

func TestWebhookStopsWhenContextEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := (&Webhook{Backoff: []time.Duration{time.Minute}}).Send(ctx, project(t, srv.URL), model.Alert{Kind: model.AlertStorm})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

func TestWebhookConfigurationErrors(t *testing.T) {
	w := &Webhook{}
	if err := w.Send(context.Background(), nil, model.Alert{}); !errors.Is(err, ErrNoWebhook) {
		t.Errorf("nil project: %v", err)
	}
	if err := w.Send(context.Background(), &model.Project{}, model.Alert{}); !errors.Is(err, ErrNoWebhook) {
		t.Errorf("no file: %v", err)
	}
	if err := w.Send(context.Background(), &model.Project{Alerts: model.AlertConfig{WebhookURLFile: "/nonexistent/url"}}, model.Alert{}); err == nil {
		t.Error("missing file accepted")
	}
	err := w.Send(context.Background(), project(t, "not a url with secret-path"), model.Alert{})
	if err == nil || strings.Contains(err.Error(), "secret-path") {
		t.Errorf("bad URL: %v", err)
	}
}

func TestHeartbeatPingsOnlyWhileHealthy(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer srv.Close()
	var healthy atomic.Bool
	healthy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	h := &Heartbeat{URL: srv.URL, Interval: 5 * time.Millisecond, Healthy: healthy.Load}
	done := h.Start(ctx)
	waitFor(t, func() bool { return n.Load() >= 3 })

	healthy.Store(false)
	time.Sleep(30 * time.Millisecond) // let a ping in flight land
	silent := n.Load()
	time.Sleep(60 * time.Millisecond)
	if got := n.Load(); got != silent {
		t.Fatalf("%d pings while unhealthy", got-silent)
	}

	healthy.Store(true)
	waitFor(t, func() bool { return n.Load() > silent })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the heartbeat did not stop")
	}
	stopped := n.Load()
	time.Sleep(30 * time.Millisecond)
	if n.Load() != stopped {
		t.Fatal("pings after stop")
	}
}

func TestHeartbeatOffAndFailuresNeverLogTheURL(t *testing.T) {
	select {
	case <-(&Heartbeat{}).Start(context.Background()):
	case <-time.After(time.Second):
		t.Fatal("a heartbeat without URL must be a no-op")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/ping/secret-uuid"
	srv.Close()
	var mu sync.Mutex
	var logs []string
	ctx, cancel := context.WithCancel(context.Background())
	h := &Heartbeat{URL: url, Interval: 5 * time.Millisecond, Logf: func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, f+" "+strings.Join(strings.Fields(strings.Trim(strings.Join(toStrings(a), " "), "[]")), " "))
	}}
	done := h.Start(ctx)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(logs) >= 2 })
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logs {
		if strings.Contains(l, "secret-uuid") || strings.Contains(l, srv.URL) {
			t.Fatalf("log holds the URL: %s", l)
		}
	}
}

func toStrings(args []any) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			out[i] = s
		} else if e, ok := a.(error); ok {
			out[i] = e.Error()
		}
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type failing struct{ err error }

func (f failing) Send(context.Context, *model.Project, model.Alert) error { return f.err }

func TestMultiAndRecorder(t *testing.T) {
	r1, r2 := &Recorder{}, &Recorder{}
	boom := errors.New("boom")
	m := Multi{r1, failing{boom}, nil, r2}
	p := &model.Project{Slug: "shop"}
	err := m.Send(context.Background(), p, model.Alert{Kind: model.AlertBlocked, Incident: "INC-1"})
	if !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	if err := m.Send(context.Background(), nil, model.Alert{Kind: model.AlertCapacity}); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	for _, r := range []*Recorder{r1, r2} {
		sent := r.Sent()
		if len(sent) != 2 || sent[0].Project != "shop" || sent[0].Alert.Incident != "INC-1" || sent[1].Project != "" {
			t.Fatalf("recorded %+v", sent)
		}
		if k := r.Kinds(); len(k) != 2 || k[0] != model.AlertBlocked || k[1] != model.AlertCapacity {
			t.Fatalf("kinds %v", k)
		}
	}
	if err := (Multi{r1, r2}).Send(context.Background(), p, model.Alert{}); err != nil {
		t.Fatalf("err %v", err)
	}
	r1.Err = boom
	if err := r1.Send(context.Background(), p, model.Alert{}); err != boom || len(r1.Sent()) != 4 {
		t.Fatalf("recorder error %v, %d alerts", err, len(r1.Sent()))
	}
	r1.Reset()
	if len(r1.Sent()) != 0 {
		t.Fatal("reset")
	}
}

// Finding 8: agent or signal text in an alert cannot carry links, images,
// HTML or control characters.
func TestFormatNeutralisesUntrustedText(t *testing.T) {
	evil := "see [approve here](https://evil.example/a) ![x](http://evil.example/p.png) <img src=x> <at>all</at>\x1b[31m\r\n[ref]: http://evil.example"
	title, text := Format(model.Alert{Kind: model.AlertEscalated, Project: "docflow", Incident: "INC-000001",
		Title: "t " + evil, Body: evil, URL: "https://gitlab.example.com/acme/docflow/-/merge_requests/1"})
	for _, s := range []string{title, strings.TrimSuffix(text, "https://gitlab.example.com/acme/docflow/-/merge_requests/1")} {
		for _, bad := range []string{"](", "![", "<", ">", "://", "\x1b", "\r", "]:"} {
			if strings.Contains(s, bad) {
				t.Errorf("%q survives in %q", bad, s)
			}
		}
	}
	if strings.Contains(title, "\n") {
		t.Errorf("title on several lines: %q", title)
	}
	if !strings.HasSuffix(text, "https://gitlab.example.com/acme/docflow/-/merge_requests/1") {
		t.Errorf("the core's own URL is lost: %q", text)
	}
}
