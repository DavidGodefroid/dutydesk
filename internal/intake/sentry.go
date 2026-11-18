package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// MaxFrames is the number of stack frames kept (the innermost ones).
const MaxFrames = 30

// The Sentry adapter reads the webhooks of Sentry's integration platform:
// resource "issue" (actions created, resolved, ...) and resource
// "event_alert" (action triggered). The structs below ARE the allow-list:
// what they do not name is never decoded, and what they name is kept only
// through a filter of sanitise.go (the application words the culprit, the
// exception type, the file and the function: see there). Left out on
// purpose: title,
// message, metadata.value (the exception message), exception value, frame
// variables and source context, request, user, tags, breadcrumbs,
// contexts, the actor, URLs.
type sentryPayload struct {
	Action string `json:"action"`
	Data   struct {
		Issue *sentryIssue `json:"issue"`
		Event *sentryEvent `json:"event"`
	} `json:"data"`
}

type sentryIssue struct {
	ID        json.RawMessage `json:"id"`
	ShortID   string          `json:"shortId"`
	Culprit   string          `json:"culprit"`
	Level     string          `json:"level"`
	Count     json.RawMessage `json:"count"`
	UserCount json.RawMessage `json:"userCount"`
	FirstSeen string          `json:"firstSeen"`
	LastSeen  string          `json:"lastSeen"`
	Metadata  struct {
		Type     string `json:"type"`
		Filename string `json:"filename"`
		Function string `json:"function"`
	} `json:"metadata"`
	Project struct {
		Slug string `json:"slug"`
	} `json:"project"`
}

type sentryEvent struct {
	IssueID json.RawMessage `json:"issue_id"`
	Culprit string          `json:"culprit"`
	Level   string          `json:"level"`
	// An event names its project by number; the slug is not in the payload.
	Project   json.RawMessage `json:"project"`
	Datetime  string          `json:"datetime"`
	Exception struct {
		Values []struct {
			Type       string `json:"type"`
			Stacktrace struct {
				Frames []sentryFrame `json:"frames"`
			} `json:"stacktrace"`
		} `json:"values"`
	} `json:"exception"`
}

type sentryFrame struct {
	Filename string          `json:"filename"`
	Module   string          `json:"module"`
	Function string          `json:"function"`
	Lineno   json.RawMessage `json:"lineno"`
}

// sentry turns a verified Sentry delivery into a signal, a resolution, or
// errIgnored.
func sentry(body []byte, resource, source string) (delivery, error) {
	var p sentryPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return delivery{}, errors.New("the body is not the JSON of a Sentry webhook")
	}
	if resource == "" {
		// VERIFY: Sentry sends Sentry-Hook-Resource; without it the
		// resource is taken from what the payload holds.
		switch {
		case p.Data.Issue != nil:
			resource = "issue"
		case p.Data.Event != nil:
			resource = "event_alert"
		}
	}
	switch resource {
	case "issue":
		if p.Data.Issue == nil {
			return delivery{}, errors.New("issue webhook without data.issue")
		}
		return sentryIssueDelivery(p.Action, p.Data.Issue, source)
	case "event_alert":
		if p.Action != "triggered" {
			return delivery{}, errIgnored
		}
		if p.Data.Event == nil {
			return delivery{}, errors.New("event alert without data.event")
		}
		return sentryEventDelivery(p.Data.Event, source)
	}
	// installation, comment, metric_alert, error, seer...: not followed.
	return delivery{}, errIgnored
}

func sentryIssueDelivery(action string, is *sentryIssue, source string) (delivery, error) {
	id, err := issueID(is.ID)
	if err != nil {
		return delivery{}, err
	}
	fp := "sentry:" + id
	switch action {
	case "resolved":
		return delivery{resolved: fp}, nil
	case "created":
	default:
		// assigned, archived (ignored), unresolved...
		return delivery{}, errIgnored
	}
	f := map[string]string{"issue_id": id}
	put(f, "project", strictIdent(is.Project.Slug))
	put(f, "short_id", strictIdent(is.ShortID))
	put(f, "exception_type", freeText(is.Metadata.Type))
	put(f, "culprit", freeText(is.Culprit))
	put(f, "file", freeText(is.Metadata.Filename))
	put(f, "function", freeText(is.Metadata.Function))
	put(f, "level", sentryLevel(is.Level))
	put(f, "count", number(is.Count))
	put(f, "user_count", number(is.UserCount))
	put(f, "first_seen", timestamp(is.FirstSeen))
	put(f, "last_seen", timestamp(is.LastSeen))
	return delivery{signal: &model.Signal{Fingerprint: fp, Summary: sentrySummary(source, id), Fields: f}}, nil
}

func sentryEventDelivery(ev *sentryEvent, source string) (delivery, error) {
	id, err := issueID(ev.IssueID)
	if err != nil {
		return delivery{}, err
	}
	f := map[string]string{"issue_id": id}
	put(f, "project_id", number(ev.Project))
	put(f, "culprit", freeText(ev.Culprit))
	put(f, "level", sentryLevel(ev.Level))
	put(f, "last_seen", timestamp(ev.Datetime))
	if vals := ev.Exception.Values; len(vals) > 0 {
		// The last value is the exception that was raised last.
		last := vals[len(vals)-1]
		put(f, "exception_type", freeText(last.Type))
		frames := last.Stacktrace.Frames
		if len(frames) > MaxFrames {
			// Sentry lists frames oldest call first: keep the innermost.
			frames = frames[len(frames)-MaxFrames:]
		}
		var lines []string
		for _, fr := range frames {
			file := fr.Filename
			if file == "" {
				file = fr.Module
			}
			lines = append(lines, fmt.Sprintf("%s:%s:%s", freeText(file), freeText(fr.Function), number(fr.Lineno)))
		}
		if len(lines) > 0 {
			// One frame per line, "file:function:line", innermost last.
			f["stack"] = strings.Join(lines, "\n")
			f["frames"] = strconv.Itoa(len(lines))
		}
	}
	return delivery{signal: &model.Signal{Fingerprint: "sentry:" + id, Summary: sentrySummary(source, id), Fields: f}}, nil
}

// sentrySummary names the webhook and the issue, nothing else: the core
// puts the summary in the titles of its alerts, and the source id comes
// from the configuration and the issue id passed issueID. What the
// application words (culprit, exception type, ...) is in Fields only.
func sentrySummary(source, id string) string {
	return "Sentry " + source + ": issue " + id
}

// issueID reads an issue id, a string or a number in the payload. It is
// the fingerprint's variable part: only letters, digits, '-' and '_'.
func issueID(raw json.RawMessage) (string, error) {
	id := scalar(raw)
	if id == "" || len(id) > 64 {
		return "", errors.New("missing issue id")
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
		default:
			return "", errors.New("malformed issue id")
		}
	}
	return id, nil
}

// number keeps raw only when it is a plain decimal number, or a string
// holding one.
func number(raw json.RawMessage) string {
	s := scalar(raw)
	if len(s) > 32 || !plainNumber.MatchString(s) {
		return ""
	}
	return s
}

var plainNumber = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

// scalar renders a JSON string or number; anything else is "".
func scalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if raw[0] == '"' {
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	return n.String()
}

// put keeps a value that went through a filter and is not empty.
func put(f map[string]string, k, v string) {
	if v != "" {
		f[k] = v
	}
}
