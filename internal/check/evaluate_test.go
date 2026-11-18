package check

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

type fakeReader struct {
	mu     sync.Mutex
	rows   []model.Row
	count  int
	err    error
	sqlQ   []string
	logQ   []string
	window time.Duration
}

func (f *fakeReader) SQL(_ context.Context, _ *model.Project, q string) ([]model.Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sqlQ = append(f.sqlQ, q)
	return f.rows, f.err
}

func (f *fakeReader) LogCount(_ context.Context, _ *model.Project, q string, w time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logQ = append(f.logQ, q)
	f.window = w
	return f.count, f.err
}

var (
	shop = &model.Project{Slug: "shop"}
	now  = time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)
)

func TestRender(t *testing.T) {
	f := map[string]string{"job_id": "4812", "a_b": "x", "empty": ""}
	for tmpl, want := range map[string]string{
		"stuck-job:{job_id}":   "stuck-job:4812",
		"{job_id}{a_b}{empty}": "4812x",
		"no placeholder":       "no placeholder",
	} {
		got, err := Render(tmpl, f)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v (want %q)", tmpl, got, err, want)
		}
	}
	// Same strict syntax as the configuration loader: any other brace is refused.
	for _, tmpl := range []string{"json {\"k\": 1} {", "{}{ job_id }", "{{job_id}}", "{a.b}"} {
		if _, err := Render(tmpl, f); err == nil {
			t.Errorf("%q: accepted", tmpl)
		}
	}
	_, err := Render("x:{queue}", f)
	var mf *MissingFieldError
	if !errors.As(err, &mf) || mf.Field != "queue" {
		t.Fatalf("err = %v", err)
	}
}

func TestSQLOneSignalPerRow(t *testing.T) {
	r := &fakeReader{rows: []model.Row{
		{"job_id": "4812", "status": "running", "customer_email": "<redacted>"},
		{"job_id": "4813", "status": "running", "customer_email": "<redacted>"},
	}}
	c := model.Check{ID: "stuck-jobs", Kind: model.CheckSQL, Severity: model.SevHigh, Query: "SELECT ...",
		Fingerprint: "stuck-job:{job_id}", Summary: "job {job_id} is {status}"}
	got, err := Evaluate(context.Background(), c, shop, r, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Signal{
		{Project: "shop", Source: "stuck-jobs", Fingerprint: "stuck-job:4812", Severity: model.SevHigh, Summary: "job 4812 is running",
			Fields: map[string]string{"job_id": "4812", "status": "running", "customer_email": "<redacted>"}, At: now},
		{Project: "shop", Source: "stuck-jobs", Fingerprint: "stuck-job:4813", Severity: model.SevHigh, Summary: "job 4813 is running",
			Fields: map[string]string{"job_id": "4813", "status": "running", "customer_email": "<redacted>"}, At: now},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("signals:\n got %+v\nwant %+v", got, want)
	}
	if r.sqlQ[0] != "SELECT ..." {
		t.Errorf("query: %q", r.sqlQ[0])
	}
	// The signal owns its fields.
	got[0].Fields["job_id"] = "x"
	if r.rows[0]["job_id"] != "4812" {
		t.Error("the signal shares the reader's row")
	}
}

func TestSQLMissingFieldNamesIt(t *testing.T) {
	r := &fakeReader{rows: []model.Row{{"id": "1"}}}
	for _, c := range []model.Check{
		{ID: "c", Kind: model.CheckSQL, Fingerprint: "x:{job_id}", Summary: "ok"},
		{ID: "c", Kind: model.CheckSQL, Fingerprint: "x:{id}", Summary: "job {job_id}"},
	} {
		_, err := Evaluate(context.Background(), c, shop, r, now)
		var mf *MissingFieldError
		if !errors.As(err, &mf) || mf.Field != "job_id" {
			t.Fatalf("err = %v", err)
		}
	}
}

func TestSQLCapsRows(t *testing.T) {
	r := &fakeReader{}
	for i := 0; i < MaxRows+7; i++ {
		r.rows = append(r.rows, model.Row{"id": fmt.Sprint(i)})
	}
	c := model.Check{ID: "c", Kind: model.CheckSQL, Fingerprint: "x:{id}"}
	res, err := Run(context.Background(), c, shop, r, now)
	if err != nil || len(res.Signals) != MaxRows || !res.Truncated {
		t.Fatalf("n=%d truncated=%v err=%v", len(res.Signals), res.Truncated, err)
	}
	r.rows = r.rows[:MaxRows]
	res, _ = Run(context.Background(), c, shop, r, now)
	if len(res.Signals) != MaxRows || res.Truncated {
		t.Fatalf("exactly MaxRows: n=%d truncated=%v", len(res.Signals), res.Truncated)
	}
}

func TestLogThreshold(t *testing.T) {
	c := model.Check{ID: "pdf-errors", Kind: model.CheckLog, Severity: model.SevMedium, LogQuery: "PDF render failed",
		LogWindow: 15 * time.Minute, Threshold: 10, Fingerprint: "pdf-errors", Summary: "{count} PDF errors in {window}"}
	r := &fakeReader{count: 9}
	if got, err := Evaluate(context.Background(), c, shop, r, now); err != nil || len(got) != 0 {
		t.Fatalf("under the threshold: %v %v", got, err)
	}
	r.count = 10
	got, err := Evaluate(context.Background(), c, shop, r, now)
	if err != nil || len(got) != 1 {
		t.Fatalf("at the threshold: %v %v", got, err)
	}
	want := model.Signal{Project: "shop", Source: "pdf-errors", Fingerprint: "pdf-errors", Severity: model.SevMedium,
		Summary: "10 PDF errors in 15m0s", Fields: map[string]string{"count": "10", "window": "15m0s", "threshold": "10"}, At: now}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("signal: %+v", got[0])
	}
	if r.logQ[0] != "PDF render failed" || r.window != 15*time.Minute {
		t.Errorf("query %q window %v", r.logQ[0], r.window)
	}
	c.Threshold = 0
	if _, err := Evaluate(context.Background(), c, shop, r, now); err == nil {
		t.Fatal("threshold 0: want an error")
	}
}

func TestExpect(t *testing.T) {
	sql := model.Check{ID: "load-6h", Kind: model.CheckExpect, Source: "sql", Query: "SELECT ...", Severity: model.SevCritical,
		Summary: "the 6h load did not run"}
	r := &fakeReader{rows: []model.Row{{"id": "1"}}}
	if got, err := Evaluate(context.Background(), sql, shop, r, now); err != nil || len(got) != 0 {
		t.Fatalf("present: %v %v", got, err)
	}
	r.rows = nil
	got, err := Evaluate(context.Background(), sql, shop, r, now)
	if err != nil || len(got) != 1 || got[0].Fingerprint != "load-6h" || got[0].Summary != "the 6h load did not run" || got[0].Fields["rows"] != "0" {
		t.Fatalf("absent: %+v %v", got, err)
	}

	lg := model.Check{ID: "heartbeat", Kind: model.CheckExpect, Source: "log", LogQuery: "cron ok", LogWindow: time.Hour, Threshold: 1,
		Fingerprint: "heartbeat-missing", Summary: "only {count} heartbeat in {window}"}
	r = &fakeReader{count: 1}
	if got, err := Evaluate(context.Background(), lg, shop, r, now); err != nil || len(got) != 0 {
		t.Fatalf("present: %v %v", got, err)
	}
	r.count = 0
	got, err = Evaluate(context.Background(), lg, shop, r, now)
	if err != nil || len(got) != 1 || got[0].Summary != "only 0 heartbeat in 1h0m0s" {
		t.Fatalf("absent: %+v %v", got, err)
	}

	bad := model.Check{ID: "x", Kind: model.CheckExpect, Source: "mq"}
	if _, err := Evaluate(context.Background(), bad, shop, r, now); err == nil {
		t.Fatal("unknown source: want an error")
	}
	if _, err := Evaluate(context.Background(), model.Check{ID: "x", Kind: "http"}, shop, r, now); err == nil {
		t.Fatal("unknown kind: want an error")
	}
}

func TestReaderErrorIsWrapped(t *testing.T) {
	boom := errors.New("boom")
	r := &fakeReader{err: boom}
	for _, c := range []model.Check{
		{ID: "a", Kind: model.CheckSQL},
		{ID: "b", Kind: model.CheckLog, Threshold: 1},
		{ID: "c", Kind: model.CheckExpect, Source: "sql"},
		{ID: "d", Kind: model.CheckExpect, Source: "log", Threshold: 1},
	} {
		if got, err := Evaluate(context.Background(), c, shop, r, now); !errors.Is(err, boom) || len(got) != 0 {
			t.Errorf("%s: %v %v", c.ID, got, err)
		}
	}
}

func TestStillFiring(t *testing.T) {
	c := model.Check{ID: "c", Kind: model.CheckSQL, Fingerprint: "stuck-job:{job_id}"}
	r := &fakeReader{rows: []model.Row{{"job_id": "1"}, {"job_id": "2"}}}
	for fp, want := range map[string]bool{"stuck-job:2": true, "stuck-job:3": false, AnyFingerprint: true, "": false} {
		got, err := StillFiring(context.Background(), c, shop, r, fp)
		if err != nil || got != want {
			t.Errorf("%q: %v, %v", fp, got, err)
		}
	}
	r.rows = nil
	if got, _ := StillFiring(context.Background(), c, shop, r, AnyFingerprint); got {
		t.Error("no row: any must be false")
	}
	// Truncated and not found: cannot say it is gone.
	for i := 0; i < MaxRows+1; i++ {
		r.rows = append(r.rows, model.Row{"job_id": fmt.Sprint(i)})
	}
	if got, _ := StillFiring(context.Background(), c, shop, r, "stuck-job:9999"); !got {
		t.Error("truncated: want true")
	}
	r.err = errors.New("down")
	if _, err := StillFiring(context.Background(), c, shop, r, "stuck-job:1"); err == nil {
		t.Error("want the reader's error")
	}
}
