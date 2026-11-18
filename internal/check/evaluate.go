package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// MaxRows caps the signals of one sql evaluation.
const MaxRows = 500

// AnyFingerprint asks StillFiring whether the check gives any signal at
// all (mass incidents).
const AnyFingerprint = "*"

// Result is one evaluation of a check.
type Result struct {
	Signals []model.Signal
	// Truncated: the query returned more than MaxRows rows; Signals holds
	// the first MaxRows.
	Truncated bool
}

// Evaluate runs the check once and returns its signals (at most MaxRows;
// Run also says whether rows were left out).
func Evaluate(ctx context.Context, c model.Check, p *model.Project, r model.LockReader, now time.Time) ([]model.Signal, error) {
	res, err := Run(ctx, c, p, r, now)
	return res.Signals, err
}

// Run runs the check once.
//
//   - sql: one signal per row, fingerprint and summary rendered from the
//     row's fields;
//   - log: one signal when the count over the window reaches the threshold
//     (fields: count, window, threshold);
//   - expect: one signal when the expected thing is absent: no row (sql
//     source, field rows=0) or a count under the threshold (log source).
//
// Signals carry only what the lock returned, already masked.
func Run(ctx context.Context, c model.Check, p *model.Project, r model.LockReader, now time.Time) (Result, error) {
	if p == nil {
		return Result{}, errors.New("check: no project")
	}
	if r == nil {
		return Result{}, errors.New("check: no lock reader")
	}
	switch c.Kind {
	case model.CheckSQL:
		return runSQL(ctx, c, p, r, now)
	case model.CheckLog:
		n, fields, err := logCount(ctx, c, p, r)
		if err != nil || n < c.Threshold {
			return Result{}, err
		}
		s, err := signal(c, p, fields, now)
		if err != nil {
			return Result{}, err
		}
		return Result{Signals: []model.Signal{s}}, nil
	case model.CheckExpect:
		return runExpect(ctx, c, p, r, now)
	}
	return Result{}, fmt.Errorf("check %s: unknown kind %q", c.ID, c.Kind)
}

func runSQL(ctx context.Context, c model.Check, p *model.Project, r model.LockReader, now time.Time) (Result, error) {
	rows, err := r.SQL(ctx, p, c.Query)
	if err != nil {
		return Result{}, fmt.Errorf("check %s: %w", c.ID, err)
	}
	var res Result
	if len(rows) > MaxRows {
		rows, res.Truncated = rows[:MaxRows], true
	}
	res.Signals = make([]model.Signal, 0, len(rows))
	for _, row := range rows {
		fields := make(map[string]string, len(row))
		for k, v := range row {
			fields[k] = v
		}
		s, err := signal(c, p, fields, now)
		if err != nil {
			return Result{}, err
		}
		res.Signals = append(res.Signals, s)
	}
	return res, nil
}

func runExpect(ctx context.Context, c model.Check, p *model.Project, r model.LockReader, now time.Time) (Result, error) {
	var fields map[string]string
	switch c.Source {
	case "sql":
		rows, err := r.SQL(ctx, p, c.Query)
		if err != nil {
			return Result{}, fmt.Errorf("check %s: %w", c.ID, err)
		}
		if len(rows) > 0 {
			return Result{}, nil
		}
		fields = map[string]string{"rows": "0"}
	case "log":
		n, f, err := logCount(ctx, c, p, r)
		if err != nil || n >= c.Threshold {
			return Result{}, err
		}
		fields = f
	default:
		return Result{}, fmt.Errorf("check %s: expect needs source sql or log, not %q", c.ID, c.Source)
	}
	s, err := signal(c, p, fields, now)
	if err != nil {
		return Result{}, err
	}
	return Result{Signals: []model.Signal{s}}, nil
}

func logCount(ctx context.Context, c model.Check, p *model.Project, r model.LockReader) (int, map[string]string, error) {
	if c.Threshold < 1 {
		// A threshold of 0 would fire a log check always and an expect never.
		return 0, nil, fmt.Errorf("check %s: threshold must be at least 1", c.ID)
	}
	n, err := r.LogCount(ctx, p, c.LogQuery, c.LogWindow)
	if err != nil {
		return 0, nil, fmt.Errorf("check %s: %w", c.ID, err)
	}
	return n, map[string]string{
		"count":     strconv.Itoa(n),
		"window":    c.LogWindow.String(),
		"threshold": strconv.Itoa(c.Threshold),
	}, nil
}

// signal builds the signal of fields. An empty fingerprint or summary
// template is the check's id.
func signal(c model.Check, p *model.Project, fields map[string]string, now time.Time) (model.Signal, error) {
	fpT, sumT := c.Fingerprint, c.Summary
	if fpT == "" {
		fpT = c.ID
	}
	if sumT == "" {
		sumT = c.ID
	}
	fp, err := Render(fpT, fields)
	if err != nil {
		return model.Signal{}, fmt.Errorf("check %s: fingerprint: %w", c.ID, err)
	}
	sum, err := Render(sumT, fields)
	if err != nil {
		return model.Signal{}, fmt.Errorf("check %s: summary: %w", c.ID, err)
	}
	return model.Signal{
		Project:     p.Slug,
		Source:      c.ID,
		Fingerprint: fp,
		Severity:    c.Severity,
		Summary:     sum,
		Fields:      fields,
		At:          now,
	}, nil
}

// StillFiring replays the check and reports whether fingerprint is still
// among its signals; AnyFingerprint asks for any signal. When the result
// was truncated and the fingerprint is not among the rows kept, it answers
// true: the check cannot show that the problem is gone.
func StillFiring(ctx context.Context, c model.Check, p *model.Project, r model.LockReader, fingerprint string) (bool, error) {
	res, err := Run(ctx, c, p, r, time.Now())
	if err != nil {
		return false, err
	}
	if fingerprint == AnyFingerprint {
		return len(res.Signals) > 0, nil
	}
	for _, s := range res.Signals {
		if s.Fingerprint == fingerprint {
			return true, nil
		}
	}
	return res.Truncated, nil
}
