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
	if t := strings.Join(strings.Fields(a.Title), " "); t != "" {
		title += ": " + truncate(t, 160)
	}
	var lines []string
	if body := truncate(strings.TrimSpace(a.Body), maxBody); body != "" {
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

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return strings.TrimRight(string(r[:max-1]), " \n") + "…"
}
