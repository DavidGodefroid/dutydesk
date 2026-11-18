package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func TestVerdictSchemaIsValidJSON(t *testing.T) {
	var s struct {
		Type       string                     `json:"type"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Additional *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal([]byte(VerdictSchema), &s); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if s.Type != "object" || s.Additional == nil || *s.Additional {
		t.Fatalf("schema must be a closed object: %+v", s)
	}
	if got := strings.Join(s.Required, ","); got != "outcome,summary,confidence" {
		t.Fatalf("required = %s", got)
	}
	// Every JSON field of model.Verdict is in the schema and nothing else.
	b, _ := json.Marshal(model.Verdict{
		Outcome: "x", Summary: "x", RootCause: "x", Evidence: []string{"x"}, RecheckMinutes: 1,
		Ticket: "x", MR: &model.MRProposal{}, MissingAction: &model.MissingAction{},
		Improvement: &model.Improvement{}, ActionsRun: []string{"x"}, Confidence: "x",
	})
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for f := range fields {
		if _, ok := s.Properties[f]; !ok {
			t.Errorf("schema lacks property %q", f)
		}
	}
	if len(fields) != len(s.Properties) {
		t.Errorf("schema has %d properties, model.Verdict has %d", len(s.Properties), len(fields))
	}
	for _, want := range []string{`"resolved","recheck","green_light","escalate","blocked"`, `"maxLength":2000`, `"maxItems":20`, `"maximum":1440`} {
		if !strings.Contains(VerdictSchema, want) {
			t.Errorf("schema lacks %s", want)
		}
	}
}

func TestParseVerdict(t *testing.T) {
	long := strings.Repeat("a", MaxSummaryLen+1)
	tests := []struct {
		name    string
		in      string
		wantErr string // substring; "" = valid
	}{
		{"resolved", `{"outcome":"resolved","summary":"done","confidence":"high","actions_run":["restart-job --job-id 4"]}`, ""},
		{"recheck default", `{"outcome":"recheck","summary":"still moving","confidence":"medium"}`, ""},
		{"recheck 20", `{"outcome":"recheck","summary":"s","confidence":"low","recheck_minutes":20}`, ""},
		{"recheck max", `{"outcome":"recheck","summary":"s","confidence":"low","recheck_minutes":1440}`, ""},
		{"recheck too far", `{"outcome":"recheck","summary":"s","confidence":"low","recheck_minutes":1441}`, "recheck_minutes"},
		{"recheck negative", `{"outcome":"recheck","summary":"s","confidence":"low","recheck_minutes":-1}`, "recheck_minutes"},
		{"green light", `{"outcome":"green_light","summary":"s","confidence":"high","ticket":"ssh-actions/T-42"}`, ""},
		{"green light no ticket", `{"outcome":"green_light","summary":"s","confidence":"high"}`, "ticket"},
		{"green light bad ticket", `{"outcome":"green_light","summary":"s","confidence":"high","ticket":"T-42"}`, "instance/id"},
		{"blocked", `{"outcome":"blocked","summary":"s","confidence":"high","missing_action":{"name":"requeue-doc","why":"w","title":"t","detail":"d"}}`, ""},
		{"blocked without action", `{"outcome":"blocked","summary":"s","confidence":"high"}`, "missing_action"},
		{"blocked bad name", `{"outcome":"blocked","summary":"s","confidence":"high","missing_action":{"name":"../x","why":"w","title":"t"}}`, "missing_action.name"},
		{"mr with any outcome", `{"outcome":"resolved","summary":"s","confidence":"high","mr":{"repo":"app","title":"Fix","description":"Root cause"}}`, ""},
		{"mr without repo", `{"outcome":"escalate","summary":"s","confidence":"high","mr":{"title":"Fix","description":"d"}}`, "mr.repo"},
		{"mr without description", `{"outcome":"escalate","summary":"s","confidence":"high","mr":{"repo":"app","title":"Fix"}}`, "mr.description"},
		{"improvement", `{"outcome":"escalate","summary":"s","confidence":"low","improvement":{"title":"t","observation":"o","change":"c"}}`, ""},
		{"improvement empty", `{"outcome":"escalate","summary":"s","confidence":"low","improvement":{"title":"t"}}`, "improvement.observation"},
		{"unknown outcome", `{"outcome":"fixed","summary":"s","confidence":"high"}`, "unknown outcome"},
		{"missing outcome", `{"summary":"s","confidence":"high"}`, "outcome is required"},
		{"missing summary", `{"outcome":"resolved","summary":"  ","confidence":"high"}`, "summary is required"},
		{"missing confidence", `{"outcome":"resolved","summary":"s"}`, "confidence is required"},
		{"bad confidence", `{"outcome":"resolved","summary":"s","confidence":"sure"}`, "unknown confidence"},
		{"summary too long", `{"outcome":"resolved","summary":"` + long + `","confidence":"high"}`, "too long"},
		{"too much evidence", `{"outcome":"resolved","summary":"s","confidence":"high","evidence":[` + strings.TrimSuffix(strings.Repeat(`"e",`, MaxEvidenceItems+1), ",") + `]}`, "too many items"},
		{"unknown field", `{"outcome":"resolved","summary":"s","confidence":"high","token":"x"}`, "invalid JSON"},
		{"not json", `I think it is resolved`, "invalid JSON"},
		{"trailing", `{"outcome":"resolved","summary":"s","confidence":"high"} {}`, "trailing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseVerdict([]byte(tc.in))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if v == nil || v.Outcome == "" {
					t.Fatalf("no verdict returned")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
