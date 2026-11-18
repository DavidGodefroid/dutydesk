// Package agent builds the prompt of an agent pass, launches the pass in an
// isolated container and turns its output into a validated verdict.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Bounds shared by VerdictSchema and ParseVerdict. Lengths are in Unicode
// code points, as JSON Schema counts them.
const (
	MaxSummaryLen       = 2000
	MaxRootCauseLen     = 4000
	MaxEvidenceItems    = 20
	MaxEvidenceLen      = 2000
	MaxRecheckMinutes   = 1440
	MaxTicketLen        = 200
	MaxRepoLen          = 100
	MaxTitleLen         = 200
	MaxMRDescriptionLen = 20000
	MaxActionNameLen    = 64
	MaxTextLen          = 4000 // why, observation, change, effect, risk
	MaxDetailLen        = 8000
	MaxActionsRun       = 50
	MaxActionRunLen     = 500
)

const (
	ticketPattern     = `^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`
	actionNamePattern = `^[a-z0-9][a-z0-9-]*$`
)

var (
	ticketRE     = regexp.MustCompile(ticketPattern)
	actionNameRE = regexp.MustCompile(actionNamePattern)
)

// VerdictSchema is the JSON Schema of model.Verdict, passed to
// `claude --json-schema`. It is compact JSON with sorted keys (deterministic).
//
// VERIFY: that claude's structured-output validation honours minLength,
// maxLength, maxItems, pattern and additionalProperties. ParseVerdict enforces
// the same bounds again, so an ignored keyword only costs a failed pass.
var VerdictSchema = buildVerdictSchema()

type obj = map[string]any

func str(max int) obj { return obj{"type": "string", "maxLength": max} }

func reqStr(max int) obj { return obj{"type": "string", "minLength": 1, "maxLength": max} }

func buildVerdictSchema() string {
	schema := obj{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"outcome", "summary", "confidence"},
		"properties": obj{
			"outcome": obj{
				"type": "string",
				"enum": []string{
					string(model.OutcomeResolved), string(model.OutcomeRecheck),
					string(model.OutcomeGreenLight), string(model.OutcomeEscalate),
					string(model.OutcomeBlocked),
				},
			},
			"summary":    reqStr(MaxSummaryLen),
			"root_cause": str(MaxRootCauseLen),
			"evidence": obj{
				"type": "array", "maxItems": MaxEvidenceItems, "items": str(MaxEvidenceLen),
			},
			"recheck_minutes": obj{"type": "integer", "minimum": 0, "maximum": MaxRecheckMinutes},
			"ticket":          obj{"type": "string", "maxLength": MaxTicketLen, "pattern": ticketPattern},
			"mr": obj{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"repo", "title", "description"},
				"properties": obj{
					"repo":        reqStr(MaxRepoLen),
					"title":       reqStr(MaxTitleLen),
					"description": reqStr(MaxMRDescriptionLen),
				},
			},
			"missing_action": obj{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"name", "why", "title"},
				"properties": obj{
					"name":   obj{"type": "string", "minLength": 1, "maxLength": MaxActionNameLen, "pattern": actionNamePattern},
					"why":    reqStr(MaxTextLen),
					"title":  reqStr(MaxTitleLen),
					"detail": str(MaxDetailLen),
				},
			},
			"improvement": obj{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"title", "observation", "change"},
				"properties": obj{
					"title":       reqStr(MaxTitleLen),
					"observation": reqStr(MaxTextLen),
					"change":      reqStr(MaxTextLen),
					"effect":      str(MaxTextLen),
					"risk":        str(MaxTextLen),
				},
			},
			"actions_run": obj{
				"type": "array", "maxItems": MaxActionsRun, "items": str(MaxActionRunLen),
			},
			"confidence": obj{"type": "string", "enum": []string{"low", "medium", "high"}},
		},
	}
	b, err := json.Marshal(schema)
	if err != nil {
		panic("agent: verdict schema: " + err.Error())
	}
	return string(b)
}

// ParseVerdict decodes one verdict and validates it: structure and bounds as
// in VerdictSchema, then the rules that tie fields to the outcome.
func ParseVerdict(data []byte) (*model.Verdict, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v model.Verdict
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("verdict: invalid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("verdict: trailing data after the JSON object")
	}
	if err := validateVerdict(&v); err != nil {
		return nil, fmt.Errorf("verdict: %w", err)
	}
	return &v, nil
}

func validateVerdict(v *model.Verdict) error {
	switch v.Outcome {
	case model.OutcomeResolved, model.OutcomeRecheck, model.OutcomeGreenLight,
		model.OutcomeEscalate, model.OutcomeBlocked:
	case "":
		return errors.New("outcome is required")
	default:
		return fmt.Errorf("unknown outcome %q", v.Outcome)
	}
	switch v.Confidence {
	case "low", "medium", "high":
	case "":
		return errors.New("confidence is required")
	default:
		return fmt.Errorf("unknown confidence %q", v.Confidence)
	}
	if err := checkLen("summary", v.Summary, 1, MaxSummaryLen); err != nil {
		return err
	}
	if err := checkLen("root_cause", v.RootCause, 0, MaxRootCauseLen); err != nil {
		return err
	}
	if err := checkList("evidence", v.Evidence, MaxEvidenceItems, MaxEvidenceLen); err != nil {
		return err
	}
	if err := checkList("actions_run", v.ActionsRun, MaxActionsRun, MaxActionRunLen); err != nil {
		return err
	}
	// 0 means "use the runbook default" and is only meaningful with recheck.
	if v.RecheckMinutes < 0 || v.RecheckMinutes > MaxRecheckMinutes {
		return fmt.Errorf("recheck_minutes must be between 0 and %d", MaxRecheckMinutes)
	}
	if v.Ticket != "" {
		if utf8.RuneCountInString(v.Ticket) > MaxTicketLen || !ticketRE.MatchString(v.Ticket) {
			return errors.New(`ticket must look like "instance/id"`)
		}
	}
	if v.Outcome == model.OutcomeGreenLight && v.Ticket == "" {
		return errors.New(`outcome green_light needs the pending ticket ("instance/id")`)
	}
	if v.Outcome == model.OutcomeBlocked && v.MissingAction == nil {
		return errors.New("outcome blocked needs missing_action")
	}
	if m := v.MR; m != nil {
		if err := firstErr(
			checkLen("mr.repo", m.Repo, 1, MaxRepoLen),
			checkLen("mr.title", m.Title, 1, MaxTitleLen),
			checkLen("mr.description", m.Description, 1, MaxMRDescriptionLen),
		); err != nil {
			return err
		}
	}
	if m := v.MissingAction; m != nil {
		if err := firstErr(
			checkLen("missing_action.name", m.Name, 1, MaxActionNameLen),
			checkLen("missing_action.why", m.Why, 1, MaxTextLen),
			checkLen("missing_action.title", m.Title, 1, MaxTitleLen),
			checkLen("missing_action.detail", m.Detail, 0, MaxDetailLen),
		); err != nil {
			return err
		}
		if !actionNameRE.MatchString(m.Name) {
			return errors.New("missing_action.name must be lower-case letters, digits and dashes")
		}
	}
	if m := v.Improvement; m != nil {
		if err := firstErr(
			checkLen("improvement.title", m.Title, 1, MaxTitleLen),
			checkLen("improvement.observation", m.Observation, 1, MaxTextLen),
			checkLen("improvement.change", m.Change, 1, MaxTextLen),
			checkLen("improvement.effect", m.Effect, 0, MaxTextLen),
			checkLen("improvement.risk", m.Risk, 0, MaxTextLen),
		); err != nil {
			return err
		}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func checkLen(field, s string, min, max int) error {
	n := utf8.RuneCountInString(s)
	if min > 0 && strings.TrimSpace(s) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if n > max {
		return fmt.Errorf("%s is too long (%d > %d characters)", field, n, max)
	}
	return nil
}

func checkList(field string, items []string, maxItems, maxLen int) error {
	if len(items) > maxItems {
		return fmt.Errorf("%s has too many items (%d > %d)", field, len(items), maxItems)
	}
	for i, it := range items {
		if err := checkLen(fmt.Sprintf("%s[%d]", field, i), it, 0, maxLen); err != nil {
			return err
		}
	}
	return nil
}
