package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// DefaultRecheck is a runbook's recheck_default when it sets none.
const DefaultRecheck = 15 * time.Minute

// MaxGreenLightTimeout: a production write ticket expires at the hub after
// 4 hours; DutyDesk must withdraw and escalate before that.
const MaxGreenLightTimeout = 4 * time.Hour

// DefaultLimits are the budgets of a project that sets none.
func DefaultLimits() model.Limits {
	return model.Limits{
		MaxOpenPerCheck:    10,
		MaxRunsPerIncident: 6,
		MaxIncidentAge:     24 * time.Hour,
		RunTimeout:         20 * time.Minute,
		MaxTurns:           60,
		MaxParallelRuns:    2,
		GreenLightTimeout:  2 * time.Hour,
		QueueAlertAfter:    15 * time.Minute,
		RecurrenceCount:    3,
		RecurrenceWindow:   7 * 24 * time.Hour,
		ReminderEvery:      24 * time.Hour,
		MaxGreenLights:     3,
		MaxQuotaRuns:       3,
	}
}

// WithDefaults fills every zero field of l from DefaultLimits.
func WithDefaults(l model.Limits) model.Limits {
	d := DefaultLimits()
	pickInt := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	pickDur := func(v *time.Duration, def time.Duration) {
		if *v == 0 {
			*v = def
		}
	}
	pickInt(&l.MaxOpenPerCheck, d.MaxOpenPerCheck)
	pickInt(&l.MaxRunsPerIncident, d.MaxRunsPerIncident)
	pickDur(&l.MaxIncidentAge, d.MaxIncidentAge)
	pickDur(&l.RunTimeout, d.RunTimeout)
	pickInt(&l.MaxTurns, d.MaxTurns)
	pickInt(&l.MaxParallelRuns, d.MaxParallelRuns)
	pickDur(&l.GreenLightTimeout, d.GreenLightTimeout)
	pickDur(&l.QueueAlertAfter, d.QueueAlertAfter)
	pickInt(&l.RecurrenceCount, d.RecurrenceCount)
	pickDur(&l.RecurrenceWindow, d.RecurrenceWindow)
	pickDur(&l.ReminderEvery, d.ReminderEvery)
	pickInt(&l.MaxGreenLights, d.MaxGreenLights)
	pickInt(&l.MaxQuotaRuns, d.MaxQuotaRuns)
	return l
}

// ValidateLimits checks limits after defaults. Errors start with the
// project.yaml key.
func ValidateLimits(l model.Limits) error {
	var errs []error
	intIn := func(key string, v, lo, hi int) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("limits.%s: %d is outside [%d, %d]", key, v, lo, hi))
		}
	}
	durIn := func(key string, v, lo, hi time.Duration) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("limits.%s: %s is outside [%s, %s]", key, v, lo, hi))
		}
	}
	intIn("max_open_per_check", l.MaxOpenPerCheck, 1, 1000)
	intIn("max_runs_per_incident", l.MaxRunsPerIncident, 1, 50)
	durIn("max_incident_age", l.MaxIncidentAge, 10*time.Minute, 30*24*time.Hour)
	durIn("run_timeout", l.RunTimeout, time.Minute, 2*time.Hour)
	intIn("max_turns", l.MaxTurns, 5, 500)
	intIn("max_parallel_runs", l.MaxParallelRuns, 1, 32)
	durIn("green_light_timeout", l.GreenLightTimeout, time.Minute, MaxGreenLightTimeout)
	durIn("queue_alert_after", l.QueueAlertAfter, time.Minute, 24*time.Hour)
	intIn("recurrence_count", l.RecurrenceCount, 2, 1000)
	durIn("recurrence_window", l.RecurrenceWindow, time.Hour, 365*24*time.Hour)
	durIn("reminder_every", l.ReminderEvery, 10*time.Minute, 30*24*time.Hour)
	intIn("max_green_lights", l.MaxGreenLights, 1, 20)
	intIn("max_quota_runs", l.MaxQuotaRuns, 1, 20)
	return errors.Join(errs...)
}
