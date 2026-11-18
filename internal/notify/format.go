// Package notify sends DutyDesk alerts and notices to humans and pings the
// dead-man switch that watches DutyDesk itself.
package notify

import (
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// maxBody is the longest alert body sent, in characters.
const maxBody = 600

var kindLabels = map[model.AlertKind]string{
	model.AlertEscalated:  "Escalated",
	model.AlertBlocked:    "Blocked, action missing",
	model.AlertGreenLight: "Green light needed",
	model.AlertCapacity:   "Capacity exhausted",
	model.AlertLocksDown:  "Locks unavailable",
	model.AlertSeatExpiry: "Seat token expiring",
	model.AlertStorm:      "Alert storm",
	model.AlertReminder:   "Reminder",
	model.AlertSystem:     "DutyDesk needs attention",
	model.NoticeMROpened:  "Merge request opened",
	model.NoticeConfigMR:  "Config merge request opened",
}

// greenLightHint tells where a green-light request is answered.
const greenLightHint = "To answer: approve or deny on the paired phone, or run `lox approve` on the host."

// KindLabel is the short English name of an alert kind.
func KindLabel(k model.AlertKind) string {
	if l, ok := kindLabels[k]; ok {
		return l
	}
	return string(k)
}

// Format renders an alert for humans: a one-line title and a short text
// (body cut to about 600 characters, where to answer a green light, the URL).
func Format(a model.Alert) (title, text string) {
	parts := []string{KindLabel(a.Kind)}
	if a.Project != "" {
		parts = append(parts, a.Project)
	}
	if a.Incident != "" {
		parts = append(parts, a.Incident)
	}
	title = "[DutyDesk] " + strings.Join(parts, " · ")
	if t := Neutralise(model.CleanLine(a.Title)); t != "" {
		title += ": " + truncate(t, 160)
	}
	var lines []string
	if body := truncate(strings.TrimSpace(Neutralise(a.Body)), maxBody); body != "" {
		lines = append(lines, body)
	}
	if a.Kind == model.AlertGreenLight {
		lines = append(lines, greenLightHint)
	}
	if a.URL != "" {
		lines = append(lines, a.URL)
	}
	return title, strings.Join(lines, "\n")
}

var neutraliser = strings.NewReplacer(
	"<", "‹", ">", "›", // no HTML tag, no autolink <http://…>, no <at> mention
	"](", "] (", // no inline Markdown link or image target
	"![", "! [", // no image
	"]:", "] :", // no reference-style link definition
	"://", "[:]//", // no bare URL a chat client would make clickable
)

// Neutralise makes text that may come from an agent or a signal inert in an
// alert: control characters are stripped, HTML and Markdown links / images
// are broken and URLs are defanged, so that an alert can show attacker-
// chosen words but never a clickable link, an image fetch or markup. The
// URL field of an alert is set by the core and is not part of this.
func Neutralise(s string) string {
	return neutraliser.Replace(model.CleanText(s))
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return strings.TrimRight(string(r[:max-1]), " \n") + "…"
}
