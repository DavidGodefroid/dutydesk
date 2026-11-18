package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// streamEvent is the subset of a `claude -p --output-format stream-json` line
// the launcher reads. Shapes confirmed against the SDK message schemas
// embedded in claude 2.1.327 (not against a live session):
//
//	{"type":"result","subtype":"success"|"error_during_execution"|"error_max_turns"|
//	 "error_max_budget_usd"|"error_max_structured_output_retries","is_error":bool,
//	 "num_turns":int,"total_cost_usd":number,"usage":{"input_tokens":..,"output_tokens":..,
//	 "cache_creation_input_tokens":..,"cache_read_input_tokens":..},
//	 "result":string,"structured_output":any,"api_error_status":int|null}
//	{"type":"rate_limit_event","rate_limit_info":{"status":"allowed"|"allowed_warning"|"rejected",
//	 "resetsAt":int,"rateLimitType":"five_hour"|"seven_day"|...}}
//
// Fields whose type is not certain are kept raw so that a surprise never
// makes the whole line unreadable.
type streamEvent struct {
	Type             string          `json:"type"`
	Subtype          string          `json:"subtype"`
	IsError          bool            `json:"is_error"`
	NumTurns         int             `json:"num_turns"`
	TotalCostUSD     float64         `json:"total_cost_usd"`
	Usage            *streamUsage    `json:"usage"`
	Result           json.RawMessage `json:"result"`
	StructuredOutput json.RawMessage `json:"structured_output"`
	APIErrorStatus   *int            `json:"api_error_status"`
	Errors           json.RawMessage `json:"errors"`
	Error            json.RawMessage `json:"error"`
	RateLimitInfo    *rateLimitInfo  `json:"rate_limit_info"`
}

type streamUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

type rateLimitInfo struct {
	Status string `json:"status"`
	// VERIFY: resetsAt is an integer in the schema; assumed to be Unix
	// seconds (a value above 1e12 is read as milliseconds).
	ResetsAt      int64  `json:"resetsAt"`
	RateLimitType string `json:"rateLimitType"`
}

// maxParsedLine bounds the memory spent on one stream-json line. A longer
// line still goes to the transcript but is not parsed.
const maxParsedLine = 32 << 20

// transcript receives the container's stdout: it writes every line to the
// transcript file with the secrets scrubbed, and remembers the events the
// launcher needs. Writes come from a single goroutine (the Runner).
type transcript struct {
	out     io.Writer
	secrets [][]byte
	buf     []byte
	skip    bool // current line overflowed maxParsedLine
	werr    error
	started bool // at least one JSON event was read

	result         *streamEvent // last result event
	rejected       bool         // a rate_limit_event said "rejected"
	rejectedReset  int64
	assistantError string // last assistant-level error tag (e.g. "rate_limit")
}

func newTranscript(out io.Writer, secrets ...string) *transcript {
	t := &transcript{out: out}
	for _, s := range secrets {
		if s != "" {
			t.secrets = append(t.secrets, []byte(s))
		}
	}
	return t
}

func (t *transcript) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			t.buf = append(t.buf, p...)
			if len(t.buf) > maxParsedLine {
				t.flush(false)
			}
			break
		}
		t.buf = append(t.buf, p[:i+1]...)
		t.flush(true)
		p = p[i+1:]
	}
	// Never fail the copy: a full disk must not block the container's stdout.
	return n, nil
}

// Close flushes a last line that has no newline.
func (t *transcript) Close() error {
	if len(t.buf) > 0 {
		t.flush(true)
	}
	return t.werr
}

// flush writes the buffered bytes; complete tells whether they end a line.
func (t *transcript) flush(complete bool) {
	line := t.buf
	if complete && !t.skip {
		t.parse(line)
	}
	if _, err := t.out.Write(scrub(line, t.secrets)); err != nil && t.werr == nil {
		t.werr = err
	}
	t.buf = t.buf[:0]
	t.skip = !complete
}

func (t *transcript) parse(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return
	}
	var ev streamEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return
	}
	t.started = true
	switch ev.Type {
	case "result":
		t.result = &ev
	case "rate_limit_event":
		if ri := ev.RateLimitInfo; ri != nil {
			// A later "allowed" does not clear the flag: it is only used
			// when the pass ends without a usable result.
			if ri.Status == "rejected" {
				t.rejected = true
				t.rejectedReset = ri.ResetsAt
			}
		}
	case "assistant":
		// VERIFY: an assistant message that stands for an API error carries
		// "error":"rate_limit"|"billing_error"|"authentication_failed"|... .
		if s := rawString(ev.Error); s != "" {
			t.assistantError = s
		}
	}
}

func scrub(b []byte, secrets [][]byte) []byte {
	for _, s := range secrets {
		if bytes.Contains(b, s) {
			b = bytes.ReplaceAll(b, s, []byte("[redacted]"))
		}
	}
	return b
}

// rawString returns a JSON string value, or the raw text for anything else
// (null and empty give "").
func rawString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// VERIFY: the wording of usage-limit messages. These patterns come from the
// strings of claude 2.1.327 ("usage limit reached", "You've hit your session
// limit", "You're out of usage credits", "resets at 3pm") and from the older
// "Claude AI usage limit reached|<unix>" form; none was observed live. They
// are only applied to error text produced by the CLI itself (an error result,
// an assistant-level error tag, stderr), never to tool output or model text.
var (
	quotaTextRE  = regexp.MustCompile(`(?i)usage limit|hit your [a-z0-9' -]{0,40}limit|reached your [a-z0-9' -]{0,40}limit|limit reached|out of (extra )?usage|rate[ _-]?limit|too many requests|\b429\b`)
	resetEpochRE = regexp.MustCompile(`(?i)limit reached\|(\d{9,13})`)
	resetClockRE = regexp.MustCompile(`(?i)resets?(?: at)? (\d{1,2})(?::(\d{2}))?\s*(am|pm)(?:\s*\(([A-Za-z_]+/[A-Za-z_/+-]+|UTC)\))?`)
)

func looksLikeQuota(text string) bool { return quotaTextRE.MatchString(text) }

// maxResetAhead rejects absurd reset times (the longest window is weekly;
// spend limits are monthly).
const maxResetAhead = 32 * 24 * time.Hour

func fromEpoch(v int64, now time.Time) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	if v > 1e12 {
		v /= 1000
	}
	return saneReset(time.Unix(v, 0), now)
}

func saneReset(t, now time.Time) time.Time {
	if !t.After(now) || t.Sub(now) > maxResetAhead {
		return time.Time{}
	}
	return t
}

// resetFromText extracts a reset time from a limit message; zero if none.
func resetFromText(text string, now time.Time) time.Time {
	if m := resetEpochRE.FindStringSubmatch(text); m != nil {
		if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			if t := fromEpoch(v, now); !t.IsZero() {
				return t
			}
		}
	}
	if m := resetClockRE.FindStringSubmatch(text); m != nil {
		hour, _ := strconv.Atoi(m[1])
		min := 0
		if m[2] != "" {
			min, _ = strconv.Atoi(m[2])
		}
		if hour < 1 || hour > 12 || min > 59 {
			return time.Time{}
		}
		hour %= 12
		if strings.EqualFold(m[3], "pm") {
			hour += 12
		}
		loc := now.Location()
		if m[4] != "" {
			if l, err := time.LoadLocation(m[4]); err == nil {
				loc = l
			}
		}
		n := now.In(loc)
		t := time.Date(n.Year(), n.Month(), n.Day(), hour, min, 0, 0, loc)
		if !t.After(n) {
			t = t.AddDate(0, 0, 1)
		}
		return saneReset(t, now)
	}
	return time.Time{}
}
