package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// MaxFrames is the number of stack frames kept (the innermost ones).
const MaxFrames = 30

// The Sentry adapter reads the webhooks of Sentry's integration platform:
// resource "issue" (actions created, resolved, ...) and resource
// "event_alert" (action triggered). The structs below ARE the allow-list:
// what they do not name is never decoded. Left out on purpose: title,
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
func sentry(body []byte, resource string) (delivery, error) {
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
		return sentryIssueDelivery(p.Action, p.Data.Issue)
	case "event_alert":
		if p.Action != "triggered" {
			return delivery{}, errIgnored
		}
		if p.Data.Event == nil {
			return delivery{}, errors.New("event alert without data.event")
		}
		return sentryEventDelivery(p.Data.Event)
	}
	// installation, comment, metric_alert, error, seer...: not followed.
	return delivery{}, errIgnored
}

func sentryIssueDelivery(action string, is *sentryIssue) (delivery, error) {
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
	put(f, "project", is.Project.Slug)
	put(f, "short_id", is.ShortID)
	put(f, "exception_type", is.Metadata.Type)
	put(f, "culprit", is.Culprit)
	put(f, "file", is.Metadata.Filename)
	put(f, "function", is.Metadata.Function)
	put(f, "level", is.Level)
	put(f, "count", number(is.Count))
	put(f, "user_count", number(is.UserCount))
	put(f, "first_seen", is.FirstSeen)
	put(f, "last_seen", is.LastSeen)
	return delivery{signal: &model.Signal{Fingerprint: fp, Summary: sentrySummary(f), Fields: f}}, nil
}

func sentryEventDelivery(ev *sentryEvent) (delivery, error) {
	id, err := issueID(ev.IssueID)
	if err != nil {
		return delivery{}, err
	}
	f := map[string]string{"issue_id": id}
	put(f, "project_id", number(ev.Project))
	put(f, "culprit", ev.Culprit)
	put(f, "level", ev.Level)
	put(f, "last_seen", ev.Datetime)
	if vals := ev.Exception.Values; len(vals) > 0 {
		// The last value is the exception that was raised last.
		last := vals[len(vals)-1]
		put(f, "exception_type", last.Type)
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
			lines = append(lines, fmt.Sprintf("%s:%s:%s", clean(file), clean(fr.Function), number(fr.Lineno)))
		}
		if len(lines) > 0 {
			// One frame per line, "file:function:line", innermost last.
			f["stack"] = strings.Join(lines, "\n")
			f["frames"] = strconv.Itoa(len(lines))
		}
	}
	return delivery{signal: &model.Signal{Fingerprint: "sentry:" + id, Summary: sentrySummary(f), Fields: f}}, nil
}

// sentrySummary is built from allow-listed fields only, never from the
// issue's title.
func sentrySummary(f map[string]string) string {
	s := "Sentry"
	if v := f["level"]; v != "" {
		s += " " + v
	}
	if v := f["exception_type"]; v != "" {
		s += ": " + v
	}
	if v := f["culprit"]; v != "" {
		s += " in " + v
	}
	if v := f["short_id"]; v != "" {
		s += " (" + v + ")"
	} else {
		s += " (issue " + f["issue_id"] + ")"
	}
	return s
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

// number keeps raw only when it is a number, or a string holding one.
func number(raw json.RawMessage) string {
	s := scalar(raw)
	if _, err := strconv.ParseFloat(s, 64); err != nil {
		return ""
	}
	return s
}

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

func put(f map[string]string, k, v string) {
	if v = clean(v); v != "" {
		f[k] = v
	}
}
