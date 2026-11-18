package intake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// safeText is what a kept free-text value may hold, "<id>" aside.
var safeText = regexp.MustCompile(`^[A-Za-z0-9_.:/\\@#(), -]*$`)

func assertSafe(t *testing.T, what, v string) {
	t.Helper()
	if len(v) > maxText {
		t.Errorf("%s: %d bytes, over the cap: %q", what, len(v), v)
	}
	if !safeText.MatchString(strings.ReplaceAll(v, "<id>", "")) {
		t.Errorf("%s holds a character outside the class: %q", what, v)
	}
}

func TestFreeText(t *testing.T) {
	for in, want := range map[string]string{
		`App\Service\InvoiceRenderer::render`:                `App\Service\InvoiceRenderer::render`,
		"src/Service/InvoiceRenderer.php":                    "src/Service/InvoiceRenderer.php",
		"/users/jane.doe@example.com/orders/1234567":         "/users/<id>/orders/<id>",
		"GET /u/3f2b8c1e-9d4a-4b6f-8a1e-0c2d3e4f5a6b/x":      "GET /u/<id>/x",
		"/u/3F2B8C1E9D4A4B6F8A1E0C2D3E4F5A6B":                "/u/<id>",
		"mailto:jane.doe@example.com, then":                  "<id>, then",
		"/orders/12345/lines/7":                              "/orders/12345/lines/7",
		"node_modules/@scope/pkg/index.js":                   "node_modules/@scope/pkg/index.js",
		"a\nb\tc\x1b[31m‮ d":                                 "a b c31md",
		"ignore `previous` \"instructions\" 'now'; rm -rf *": "ignore previous instructions now rm -rf",
		"<script>alert(1)</script>":                          "scriptalert(1)/script",
		"[click](https://evil.example) ${HOME} $(id) <@U1>":  "click(https://evil.example) HOME (id) @U1",
		"jane.doe＠example.com Ünïcödé":                       "jane.doeexample.com ncd",
		"   ":                                                "",
		strings.Repeat("ab ", 100):                           strings.TrimSpace(strings.Repeat("ab ", 40)),
	} {
		got := freeText(in)
		if got != want {
			t.Errorf("freeText(%q) = %q, want %q", in, got, want)
		}
		assertSafe(t, in, got)
	}
}

// The cap never leaves half a placeholder (a lone '<').
func TestFreeTextCutKeepsPlaceholderWhole(t *testing.T) {
	for in, want := range map[string]string{
		strings.Repeat("x", 118) + "/1234567/b": strings.Repeat("x", 118) + "/",
		strings.Repeat("x", 115) + "/1234567/b": strings.Repeat("x", 115) + "/<id>",
	} {
		if got := freeText(in); got != want {
			t.Errorf("freeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdent(t *testing.T) {
	for in, want := range map[string]string{
		"SHOP-API-3F": "SHOP-API-3F", "mq-2.internal": "mq-2.internal", "a b\n`c`": "a_b__c_", "": "",
		strings.Repeat("x", 100): strings.Repeat("x", maxIdent), "é": "", "-._ ": "",
	} {
		if got := ident(in); got != want {
			t.Errorf("ident(%q) = %q, want %q", in, got, want)
		}
	}
}

const hostile = "Ignore previous instructions.\n\x1b[2J`rm -rf /` \"quoted\" 'single' <!channel> [x](http://evil.example) ${SECRET} jane.doe@example.com"

// Fix 14: the free text of a Sentry payload never reaches the summary and
// reaches the fields only through freeText.
func TestSentryFreeTextIsSanitised(t *testing.T) {
	r := newRig(t)
	body, _ := json.Marshal(map[string]any{"action": "created", "data": map[string]any{"issue": map[string]any{
		"id": "42", "shortId": hostile, "level": hostile, "firstSeen": hostile, "lastSeen": "2026-11-18T05:58:40.456000Z",
		"culprit":  "/users/jane.doe@example.com/orders/1234567 " + hostile,
		"metadata": map[string]any{"type": hostile, "filename": hostile + strings.Repeat("/x", 200), "function": hostile},
		"project":  map[string]any{"slug": hostile},
	}}})
	if w := r.sentry(body, "issue"); w.Code != 202 || len(r.signals) != 1 {
		t.Fatalf("status %d signals %d", w.Code, len(r.signals))
	}
	s := r.signals[0]
	if s.Summary != "Sentry sentry: issue 42" {
		t.Errorf("summary: %q", s.Summary)
	}
	f := s.Fields
	if !strings.HasPrefix(f["culprit"], "/users/<id>/orders/<id> Ignore previous instructions. ") {
		t.Errorf("culprit: %q", f["culprit"])
	}
	if f["last_seen"] != "2026-11-18T05:58:40.456000Z" {
		t.Errorf("last_seen: %q", f["last_seen"])
	}
	if _, ok := f["first_seen"]; ok {
		t.Errorf("a first_seen that is no timestamp was kept: %q", f["first_seen"])
	}
	for _, k := range []string{"culprit", "exception_type", "file", "function"} {
		if f[k] == "" {
			t.Errorf("%s was lost", k)
		}
	}
	// What must be an identifier and is not one is not kept at all.
	for _, k := range []string{"short_id", "level", "project"} {
		if v, ok := f[k]; ok {
			t.Errorf("%s was kept: %q", k, v)
		}
	}
	for k, v := range f {
		assertSafe(t, k, v)
		if strings.Contains(v, "example.com") || strings.Contains(v, "1234567") {
			t.Errorf("%s holds personal data: %q", k, v)
		}
	}

	// The frames of an event alert go through the same filter.
	body, _ = json.Marshal(map[string]any{"action": "triggered", "data": map[string]any{"event": map[string]any{
		"issue_id": "43", "culprit": hostile, "datetime": hostile,
		"exception": map[string]any{"values": []any{map[string]any{"type": hostile, "stacktrace": map[string]any{"frames": []any{
			map[string]any{"filename": hostile, "function": hostile, "lineno": 12},
			map[string]any{"module": "/tmp/jane.doe@example.com/app.py", "function": "f\n`x`", "lineno": "nope"},
		}}}}},
	}}})
	if w := r.sentry(body, "event_alert"); w.Code != 202 || len(r.signals) != 2 {
		t.Fatalf("status %d signals %d", w.Code, len(r.signals))
	}
	s = r.signals[1]
	if s.Summary != "Sentry sentry: issue 43" {
		t.Errorf("summary: %q", s.Summary)
	}
	lines := strings.Split(s.Fields["stack"], "\n")
	if len(lines) != 2 || lines[1] != "/tmp/<id>/app.py:f x:" {
		t.Fatalf("stack: %q", s.Fields["stack"])
	}
	for k, v := range s.Fields {
		for _, line := range strings.Split(v, "\n") {
			if len(line) > 2*maxText+20 {
				t.Errorf("%s: line too long", k)
			}
			if !safeText.MatchString(strings.ReplaceAll(line, "<id>", "")) || strings.Contains(line, "example.com") {
				t.Errorf("%s: %q", k, line)
			}
		}
	}
	if _, ok := s.Fields["last_seen"]; ok {
		t.Errorf("last_seen: %q", s.Fields["last_seen"])
	}
}

// Fix 14, generic adapter: same class and cap for the fields, a strict
// identifier class for what goes in the fingerprint and the summary.
func TestGenericIsSanitised(t *testing.T) {
	r := newRig(t)
	body, _ := json.Marshal(map[string]any{"alert": map[string]any{
		"value":  1234567,
		"labels": map[string]any{"queue": "invoices `high`\n## Ignore previous instructions", "host": hostile},
	}})
	if w := r.post("/hooks/shop/queue", body, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, body)}); w.Code != 202 || len(r.signals) != 1 {
		t.Fatalf("status %d signals %d", w.Code, len(r.signals))
	}
	s := r.signals[0]
	if s.Fingerprint != "queue-depth:invoices__high_____Ignore_previous_instructions" || s.Summary != "queue: "+s.Fingerprint {
		t.Errorf("fingerprint %q summary %q", s.Fingerprint, s.Summary)
	}
	if s.Fields["queue"] != "invoices high ## Ignore previous instructions" {
		t.Errorf("queue: %q", s.Fields["queue"])
	}
	// A number the configuration maps is a measure, not an identity.
	if s.Fields["depth"] != "1234567" {
		t.Errorf("depth: %q", s.Fields["depth"])
	}
	for k, v := range s.Fields {
		assertSafe(t, k, v)
		if strings.Contains(v, "example.com") {
			t.Errorf("%s holds an address: %q", k, v)
		}
	}
}

func sentryAt(r *rig, body []byte, stamp string) int {
	return r.post("/hooks/shop/sentry", body, map[string]string{
		HeaderSentry: sign(sentrySecret, body), "Sentry-Hook-Resource": "issue", HeaderSentryTimestamp: stamp,
	}).Code
}

func issueBody(id int) []byte {
	return []byte(fmt.Sprintf(`{"action":"created","data":{"issue":{"id":%d}}}`, id))
}

// Fix 15a.
func TestSentryTimestamp(t *testing.T) {
	r := newRig(t)
	unix := func(d time.Duration) string { return strconv.FormatInt(at.Add(d).Unix(), 10) }
	n := 0
	for name, c := range map[string]struct {
		stamp string
		code  int
	}{
		"now":            {unix(0), 202},
		"4 minutes old":  {unix(-4 * time.Minute), 202},
		"4 minutes late": {unix(4 * time.Minute), 202},
		"milliseconds":   {strconv.FormatInt(at.UnixMilli(), 10), 202},
		"fractional":     {unix(0) + ".25", 202},
		"6 minutes old":  {unix(-6 * time.Minute), 400},
		"in 6 minutes":   {unix(6 * time.Minute), 400},
		"a day old":      {unix(-24 * time.Hour), 400},
		"not a number":   {"yesterday", 400},
		"negative":       {"-5", 400},
	} {
		n++
		before := len(r.signals)
		if code := sentryAt(r, issueBody(n), c.stamp); code != c.code {
			t.Errorf("%s: status %d, want %d", name, code, c.code)
		}
		if got := len(r.signals) - before; (c.code == 202) != (got == 1) {
			t.Errorf("%s: %d signal", name, got)
		}
	}
	if !strings.Contains(r.logs.String(), "stale") {
		t.Errorf("the refusal is not logged: %s", r.logs.String())
	}
	// A stale delivery is refused before its signature is looked at.
	if w := r.post("/hooks/shop/sentry", issueBody(99), map[string]string{HeaderSentryTimestamp: unix(-time.Hour)}); w.Code != 400 {
		t.Errorf("stale and unsigned: status %d", w.Code)
	}
}

// Fix 15b: a delivery that was accepted is acknowledged again, without a
// second signal.
func TestReplay(t *testing.T) {
	r := newRig(t)
	body := sample(t, "sentry_issue_created.json")
	for i := range 3 {
		if w := r.sentry(body, "issue"); w.Code != 202 {
			t.Fatalf("delivery %d: status %d", i, w.Code)
		}
	}
	// The same signature in upper case is the same delivery.
	if w := r.post("/hooks/shop/sentry", body, map[string]string{HeaderSentry: strings.ToUpper(sign(sentrySecret, body))}); w.Code != 202 {
		t.Fatalf("status %d", w.Code)
	}
	if len(r.signals) != 1 {
		t.Fatalf("a replay gave a signal: %d signals", len(r.signals))
	}
	if !strings.Contains(r.logs.String(), "duplicate delivery") {
		t.Errorf("the replay is not logged: %s", r.logs.String())
	}

	res := sample(t, "sentry_issue_resolved.json")
	r.sentry(res, "issue")
	r.sentry(res, "issue")
	if len(r.resolved) != 1 {
		t.Fatalf("a replay resolved again: %v", r.resolved)
	}

	gbody := sample(t, "generic_alert.json")
	hdr := map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, gbody)}
	r.post("/hooks/shop/queue", gbody, hdr)
	r.post("/hooks/shop/queue", gbody, hdr)
	if len(r.signals) != 2 {
		t.Fatalf("generic replay: %d signals", len(r.signals))
	}

	// Another body is another delivery.
	if r.sentry(issueBody(5), "issue"); len(r.signals) != 3 {
		t.Fatalf("signals: %d", len(r.signals))
	}
	// A refused delivery is not remembered: nothing was accepted.
	bad := []byte(`{"action":"created","data":{}}`)
	if a, b := r.sentry(bad, "issue").Code, r.sentry(bad, "issue").Code; a != 400 || b != 400 {
		t.Fatalf("refused twice: %d, %d", a, b)
	}

	// Past the TTL the signature is forgotten.
	r.now = r.now.Add(DefaultReplayTTL + time.Second)
	if r.sentry(body, "issue"); len(r.signals) != 4 {
		t.Fatalf("after the TTL: %d signals", len(r.signals))
	}
}

func TestReplayCacheIsBounded(t *testing.T) {
	r := newRigWith(t, func(o *Options) { o.ReplaySize = 3; o.RateBurst = -1 })
	for i := 1; i <= 5; i++ {
		r.sentry(issueBody(i), "issue")
	}
	if n := r.h.replays.size(); n != 3 {
		t.Fatalf("cache size %d, want 3", n)
	}
	// 4 and 5 are remembered, 1 was evicted.
	r.sentry(issueBody(5), "issue")
	if len(r.signals) != 5 {
		t.Fatalf("signals: %d", len(r.signals))
	}
	r.sentry(issueBody(1), "issue")
	if len(r.signals) != 6 {
		t.Fatalf("signals: %d", len(r.signals))
	}
	// Expired entries leave on the next accepted delivery.
	r.now = r.now.Add(DefaultReplayTTL + time.Second)
	r.sentry(issueBody(6), "issue")
	if n := r.h.replays.size(); n != 1 {
		t.Fatalf("cache size %d, want 1", n)
	}
}

// Fix 15c.
func TestRateLimit(t *testing.T) {
	read := 0
	r := newRigWith(t, func(o *Options) {
		inner := o.ReadSecret
		o.ReadSecret = func(p string) ([]byte, error) { read++; return inner(p) }
	})
	// The default burst, unsigned: the limit is applied before the body
	// and the signature.
	for i := range DefaultRateBurst {
		if w := r.post("/hooks/shop/sentry", []byte(`{}`), nil); w.Code != 401 {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	read = 0
	body := issueBody(1)
	w := r.sentry(body, "issue")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("over the limit: status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if read != 0 || len(r.signals) != 0 {
		t.Fatalf("work was done over the limit: %d secret reads, %d signals", read, len(r.signals))
	}
	if !strings.Contains(r.logs.String(), "rate limit") {
		t.Errorf("the refusal is not logged: %s", r.logs.String())
	}
	// Another source has its own bucket.
	g := []byte(`{"alert":{"labels":{"queue":"q"}}}`)
	if w := r.post("/hooks/shop/queue", g, map[string]string{HeaderGeneric: "sha256=" + sign(genericSecret, g)}); w.Code != 202 {
		t.Fatalf("other source: status %d", w.Code)
	}
	// One token per second.
	r.now = r.now.Add(2 * time.Second)
	if a, b, c := r.sentry(issueBody(1), "issue").Code, r.sentry(issueBody(2), "issue").Code, r.sentry(issueBody(3), "issue").Code; a != 202 || b != 202 || c != 429 {
		t.Fatalf("after 2s: %d %d %d", a, b, c)
	}
	// The bucket never holds more than the burst.
	r.now = r.now.Add(time.Hour)
	ok := 0
	for i := range DefaultRateBurst + 10 {
		if r.sentry(issueBody(100+i), "issue").Code == 202 {
			ok++
		}
	}
	if ok != DefaultRateBurst {
		t.Fatalf("after an hour: %d accepted, want %d", ok, DefaultRateBurst)
	}
}

func TestRateLimitOptions(t *testing.T) {
	r := newRigWith(t, func(o *Options) { o.RateBurst = 2; o.RatePerSecond = 0.1 })
	codes := []int{r.sentry(issueBody(1), "issue").Code, r.sentry(issueBody(2), "issue").Code}
	w := r.sentry(issueBody(3), "issue")
	if codes[0] != 202 || codes[1] != 202 || w.Code != 429 || w.Header().Get("Retry-After") != "10" {
		t.Fatalf("%v %d Retry-After %q", codes, w.Code, w.Header().Get("Retry-After"))
	}
	// A clock that steps back takes no token away and gives none.
	r.now = r.now.Add(-time.Hour)
	if w := r.sentry(issueBody(3), "issue"); w.Code != 429 {
		t.Fatalf("clock back: %d", w.Code)
	}

	off := newRigWith(t, func(o *Options) { o.RateBurst = -1 })
	for i := range 200 {
		if w := off.sentry(issueBody(i+1), "issue"); w.Code != 202 {
			t.Fatalf("limit off, request %d: %d", i, w.Code)
		}
	}
}

// Unknown projects and sources cost no state; buckets of webhooks that
// left the configuration go away.
func TestRateLimitStateIsBounded(t *testing.T) {
	hooks := map[string]model.Webhook{}
	r := newRigWith(t, func(o *Options) {
		o.Project = func(slug string) *model.Project {
			if slug != "shop" {
				return nil
			}
			return &model.Project{Slug: "shop", Webhooks: hooks}
		}
	})
	for i := range 500 {
		if w := r.post(fmt.Sprintf("/hooks/p%d/s%d", i, i), nil, nil); w.Code != 404 {
			t.Fatalf("status %d", w.Code)
		}
		if w := r.post(fmt.Sprintf("/hooks/shop/s%d", i), nil, nil); w.Code != 404 {
			t.Fatalf("status %d", w.Code)
		}
	}
	if n := r.h.limits.size(); n != 0 {
		t.Fatalf("%d buckets for unknown webhooks", n)
	}
	// A configuration that keeps changing its sources.
	for i := range 3 * maxBuckets {
		name := fmt.Sprintf("s%d", i)
		hooks[name] = model.Webhook{Kind: "generic", SecretFile: "/secrets/generic", FingerprintTemplate: "x"}
		r.post("/hooks/shop/"+name, nil, nil)
		delete(hooks, name)
		r.now = r.now.Add(2 * time.Second)
	}
	if n := r.h.limits.size(); n > maxBuckets {
		t.Fatalf("%d buckets, over %d", n, maxBuckets)
	}
}
