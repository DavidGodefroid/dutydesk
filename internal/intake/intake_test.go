package intake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const (
	sentrySecret  = "sentry-client-secret"
	genericSecret = "generic-secret"
)

var at = time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)

// pii lists what the sample payloads hold outside the allow-list. None of
// it may reach a signal or a log line.
var pii = []string{
	"PII-", "marie", "Marie", "durand", "Durand", "paul.martin", "jdupont", "Dupont", "dupont", "example.org", "example.net", "acme",
	"hunter2", "BE68539007547034", "4111111111111111", "203.0.113.77", "Namur", "Rue de Fer", "Bearer", "session=", "token=",
	"Cannot render", "SQLSTATE", "Duplicate entry", "mdurand", "88123", "iPhone", "Firefox", "sentry.io", "shop.example", "SELECT",
	"+32470000000", "oncall", "ordered 3 books", "wiki.example", "/home/",
}

type rig struct {
	t        *testing.T
	h        *Handler
	signals  []model.Signal
	resolved []string
	logs     bytes.Buffer
	now      time.Time
}

func newRig(t *testing.T) *rig { return newRigWith(t, nil) }

// newRigWith lets a test change the options before the handler is built.
func newRigWith(t *testing.T, tune func(*Options)) *rig {
	r := &rig{t: t, now: at}
	p := &model.Project{Slug: "shop", Webhooks: map[string]model.Webhook{
		"sentry": {Kind: "sentry", SecretFile: "/secrets/sentry", Severity: model.SevHigh},
		"queue": {Kind: "generic", SecretFile: "/secrets/generic", Severity: model.SevMedium,
			FingerprintTemplate: "queue-depth:{queue}",
			Fields: map[string]string{
				"queue": "alert.labels.queue", "host": "alert.labels.host", "depth": "alert.value", "critical": "alert.critical",
				"first_target": "alert.targets.0.name", "labels": "alert.labels", "absent": "alert.nope.deeper", "oob": "alert.targets.7.name",
			}},
		"nofp":    {Kind: "generic", SecretFile: "/secrets/generic"},
		"nosec":   {Kind: "generic", SecretFile: "/secrets/missing", FingerprintTemplate: "x"},
		"empty":   {Kind: "generic", SecretFile: "/secrets/empty", FingerprintTemplate: "x"},
		"strange": {Kind: "pagerduty", SecretFile: "/secrets/generic"},
	}}
	o := Options{
		Project: func(slug string) *model.Project {
			if slug == "shop" {
				return p
			}
			return nil
		},
		Sink:     func(s model.Signal) { r.signals = append(r.signals, s) },
		Resolved: func(project, source, fp string) { r.resolved = append(r.resolved, project+"|"+source+"|"+fp) },
		ReadSecret: func(path string) ([]byte, error) {
			switch path {
			case "/secrets/sentry":
				return []byte(sentrySecret + "\n"), nil
			case "/secrets/generic":
				return []byte(genericSecret), nil
			case "/secrets/empty":
				return []byte(" \n"), nil
			}
			return nil, os.ErrNotExist
		},
		Now:    func() time.Time { return r.now },
		Logger: slog.New(slog.NewTextHandler(&r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tune != nil {
		tune(&o)
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (r *rig) post(path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func (r *rig) sentry(body []byte, resource string) *httptest.ResponseRecorder {
	return r.post("/hooks/shop/sentry", body, map[string]string{HeaderSentry: sign(sentrySecret, body), "Sentry-Hook-Resource": resource})
}

// noPII fails when v, as JSON, or the log holds a marker of the samples.
func (r *rig) noPII(v any) {
	r.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, where := range []string{string(b), r.logs.String()} {
		for _, m := range pii {
			if strings.Contains(where, m) {
				r.t.Errorf("personal data %q reached: %.300s", m, where)
			}
		}
	}
}

func TestSentryIssueCreated(t *testing.T) {
	r := newRig(t)
	w := r.sentry(sample(t, "sentry_issue_created.json"), "issue")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	want := []model.Signal{{
		Project: "shop", Source: "sentry", Fingerprint: "sentry:4509877862", Severity: model.SevHigh,
		Summary: "Sentry sentry: issue 4509877862",
		Fields: map[string]string{
			"issue_id": "4509877862", "project": "shop-api", "short_id": "SHOP-API-3F",
			"exception_type": `App\Exception\RenderException`, "culprit": `App\Service\InvoiceRenderer::render`,
			"file": "src/Service/InvoiceRenderer.php", "function": "render", "level": "error",
			"count": "12", "user_count": "3",
			"first_seen": "2026-11-18T05:02:11.123000Z", "last_seen": "2026-11-18T05:58:40.456000Z",
		},
		At: at,
	}}
	if !reflect.DeepEqual(r.signals, want) {
		t.Fatalf("signals:\n got %+v\nwant %+v", r.signals, want)
	}
	r.noPII(r.signals)
	if len(r.resolved) != 0 {
		t.Fatalf("resolved: %v", r.resolved)
	}
}

func TestSentryEventAlert(t *testing.T) {
	r := newRig(t)
	if w := r.sentry(sample(t, "sentry_event_alert.json"), "event_alert"); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	if len(r.signals) != 1 {
		t.Fatalf("signals: %d", len(r.signals))
	}
	s := r.signals[0]
	if s.Fingerprint != "sentry:4509877862" || s.Severity != model.SevHigh || !s.At.Equal(at) ||
		s.Summary != "Sentry sentry: issue 4509877862" {
		t.Fatalf("signal: %+v", s)
	}
	f := s.Fields
	stack := strings.Split(f["stack"], "\n")
	if f["frames"] != "30" || len(stack) != MaxFrames {
		t.Fatalf("frames: %s / %d", f["frames"], len(stack))
	}
	// The innermost frames are kept, reduced to file:function:line.
	if stack[0] != "vendor/framework/src/Pipeline10.php:handle10:110" ||
		stack[28] != `src/Service/InvoiceRenderer.php:App\Service\InvoiceRenderer::render:212` ||
		stack[29] != `App\Pdf\Engine:App\Pdf\Engine::write:88` {
		t.Fatalf("stack: %q ... %q, %q", stack[0], stack[28], stack[29])
	}
	delete(f, "stack")
	want := map[string]string{
		"issue_id": "4509877862", "project_id": "4505321021", "culprit": `App\Service\InvoiceRenderer::render`, "level": "error",
		"last_seen": "2026-11-18T05:58:40.456000Z", "exception_type": `App\Exception\RenderException`, "frames": "30",
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("fields: %v", f)
	}
	f["stack"] = strings.Join(stack, "\n")
	r.noPII(r.signals)
}

func TestSentryResolved(t *testing.T) {
	r := newRig(t)
	if w := r.sentry(sample(t, "sentry_issue_resolved.json"), "issue"); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	if len(r.signals) != 0 || !reflect.DeepEqual(r.resolved, []string{"shop|sentry|sentry:4509877862"}) {
		t.Fatalf("signals=%v resolved=%v", r.signals, r.resolved)
	}
	r.noPII(r.resolved)
}

func TestSentryIgnoredAndMalformed(t *testing.T) {
	r := newRig(t)
	for name, c := range map[string]struct {
		body, resource string
		code           int
	}{
		"assigned":            {`{"action":"assigned","data":{"issue":{"id":"1"}}}`, "issue", 202},
		"installation":        {`{"action":"created","data":{"installation":{"uuid":"x"}}}`, "installation", 202},
		"metric alert":        {`{"action":"critical","data":{"metric_alert":{}}}`, "metric_alert", 202},
		"alert not triggered": {`{"action":"other","data":{"event":{"issue_id":"1"}}}`, "event_alert", 202},
		"not json":            {`marie.durand@example.org`, "issue", 400},
		"no issue":            {`{"action":"created","data":{}}`, "issue", 400},
		"no issue id":         {`{"action":"created","data":{"issue":{"title":"marie"}}}`, "issue", 400},
		"issue id injection":  {`{"action":"created","data":{"issue":{"id":"1 marie.durand@example.org"}}}`, "issue", 400},
		"no event":            {`{"action":"triggered","data":{}}`, "event_alert", 400},
	} {
		if w := r.sentry([]byte(c.body), c.resource); w.Code != c.code {
			t.Errorf("%s: status %d, want %d", name, w.Code, c.code)
		}
	}
	if len(r.signals) != 0 || len(r.resolved) != 0 {
		t.Fatalf("signals=%v resolved=%v", r.signals, r.resolved)
	}
	r.noPII(nil)
}

func TestSentryResourceFromPayload(t *testing.T) {
	r := newRig(t)
	body := []byte(`{"action":"created","data":{"issue":{"id":77,"level":"fatal","count":"x"}}}`)
	if w := r.sentry(body, ""); w.Code != 202 || len(r.signals) != 1 {
		t.Fatalf("status %d signals %v", w.Code, r.signals)
	}
	s := r.signals[0]
	if s.Fingerprint != "sentry:77" || s.Summary != "Sentry sentry: issue 77" || !reflect.DeepEqual(s.Fields, map[string]string{"issue_id": "77", "level": "fatal"}) {
		t.Fatalf("signal: %+v", s)
	}
}

func TestSignature(t *testing.T) {
	r := newRig(t)
	body := sample(t, "sentry_issue_created.json")
	good := sign(sentrySecret, body)
	for name, hdr := range map[string]map[string]string{
		"missing":        {},
		"wrong secret":   {HeaderSentry: sign("other", body)},
		"other body":     {HeaderSentry: sign(sentrySecret, append([]byte(" "), body...))},
		"not hex":        {HeaderSentry: "zz" + good[2:]},
		"truncated":      {HeaderSentry: good[:32]},
		"generic header": {HeaderGeneric: "sha256=" + good},
	} {
		if w := r.post("/hooks/shop/sentry", body, hdr); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	gbody := sample(t, "generic_alert.json")
	ggood := sign(genericSecret, gbody)
	for name, hdr := range map[string]map[string]string{
		"missing":       {},
		"no prefix":     {HeaderGeneric: ggood},
		"wrong secret":  {HeaderGeneric: "sha256=" + sign(sentrySecret, gbody)},
		"sentry header": {HeaderSentry: ggood},
	} {
		if w := r.post("/hooks/shop/queue", gbody, hdr); w.Code != http.StatusUnauthorized {
			t.Errorf("generic %s: status %d", name, w.Code)
		}
	}
	if len(r.signals) != 0 {
		t.Fatalf("an unsigned delivery gave a signal: %v", r.signals)
	}
	if w := r.post("/hooks/shop/sentry", body, map[string]string{HeaderSentry: strings.ToUpper(good)}); w.Code != 202 {
		t.Errorf("upper-case hex: status %d", w.Code)
	}
	r.noPII(nil)
}

func TestGeneric(t *testing.T) {
	r := newRig(t)
	body := sample(t, "generic_alert.json")
	if w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}); w.Code != 202 {
		t.Fatalf("status %d", w.Code)
	}
	want := []model.Signal{{
		Project: "shop", Source: "queue", Fingerprint: "queue-depth:invoices", Severity: model.SevMedium, Summary: "queue: queue-depth:invoices",
		Fields: map[string]string{"queue": "invoices", "host": "mq-2", "depth": "1842", "critical": "true", "first_target": "worker-a"},
		At:     at,
	}}
	if !reflect.DeepEqual(r.signals, want) {
		t.Fatalf("signals:\n got %+v\nwant %+v", r.signals, want)
	}
	r.noPII(r.signals)

	// Without the fingerprint's field: refused, no signal.
	body = []byte(`{"alert":{"labels":{"host":"mq-2"}}}`)
	if w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}); w.Code != 400 {
		t.Fatalf("missing fingerprint field: status %d", w.Code)
	}
	body = []byte(`{"alert":{"labels":{"queue":""}}}`)
	if w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}); w.Code != 400 {
		t.Fatalf("empty fingerprint field: status %d", w.Code)
	}
	if len(r.signals) != 1 {
		t.Fatalf("signals: %d", len(r.signals))
	}
}

func TestGenericValuesAreCleaned(t *testing.T) {
	r := newRig(t)
	body, _ := json.Marshal(map[string]any{"alert": map[string]any{"labels": map[string]any{"queue": "a\nb\x1b[31m" + strings.Repeat("é", 400) + strings.Repeat("z", 400)}}})
	if w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}); w.Code != 202 {
		t.Fatalf("status %d", w.Code)
	}
	q := r.signals[0].Fields["queue"]
	if len(q) != maxText || q != "a b31m"+strings.Repeat("z", maxText-6) {
		t.Fatalf("value: %q", q)
	}
}

func TestRouting(t *testing.T) {
	r := newRig(t)
	body := []byte(`{}`)
	sig := map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}
	for path, code := range map[string]int{
		"/hooks/nope/sentry":   404,
		"/hooks/shop/nope":     404,
		"/hooks/shop":          404,
		"/hooks/shop/queue/x":  404,
		"/hooks/shop/nofp":     500, // no fingerprint template
		"/hooks/shop/nosec":    500, // secret file missing
		"/hooks/shop/empty":    500, // empty secret
		"/hooks/shop/strange":  500, // unknown kind
		"/other":               404,
		"/hooks/shop/queue?x=": 400, // signed, lacks the fingerprint field
	} {
		if w := r.post(path, body, sig); w.Code != code {
			t.Errorf("%s: status %d, want %d", path, w.Code, code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/hooks/shop/queue", nil)
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", w.Code)
	}
	if len(r.signals) != 0 {
		t.Fatalf("signals: %v", r.signals)
	}
}

func TestBodyCap(t *testing.T) {
	r := newRig(t)
	pad := strings.Repeat("a", MaxBody)
	body := []byte(`{"alert":{"labels":{"queue":"q"}},"pad":"` + pad + `"}`)
	w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)})
	if w.Code != http.StatusRequestEntityTooLarge || len(r.signals) != 0 {
		t.Fatalf("status %d signals %d", w.Code, len(r.signals))
	}
	// Exactly at the cap: read whole.
	fit := []byte(`{"alert":{"labels":{"queue":"q"}},"pad":"` + pad[:MaxBody-len(`{"alert":{"labels":{"queue":"q"}},"pad":""}`)] + `"}`)
	if len(fit) != MaxBody {
		t.Fatalf("test body: %d", len(fit))
	}
	if w := r.post("/hooks/shop/queue", fit, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, fit)}); w.Code != 202 {
		t.Fatalf("at the cap: status %d", w.Code)
	}
}

func TestResponsesAndLogsHoldNoPayload(t *testing.T) {
	r := newRig(t)
	body := sample(t, "sentry_event_alert.json")
	for _, w := range []*httptest.ResponseRecorder{
		r.sentry(body, "event_alert"),
		r.post("/hooks/shop/sentry", body, map[string]string{HeaderSentry: "00"}),
		r.sentry(body[:len(body)/2], "event_alert"),
	} {
		r.noPII(w.Body.String())
	}
	if !strings.Contains(r.logs.String(), "bad signature") {
		t.Errorf("the refusal is not logged: %s", r.logs.String())
	}
}

func TestNewNeedsProjectAndSink(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error")
	}
	h, err := New(Options{Project: func(string) *model.Project { return nil }, Sink: func(model.Signal) {}})
	if err != nil || h == nil {
		t.Fatal(err)
	}
}
