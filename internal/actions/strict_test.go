package actions

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// S3: a value is made of [A-Za-z0-9._:@=+-] only, whatever its type.
func TestCheckValueStrictClass(t *testing.T) {
	for _, v := range []string{"a", "42", "night_run.1", "user@host:5432", "k=v", "a+b", "a-b", "A.B_c", "x..y", "...", "=x", "@x", ":x", "_"} {
		if err := checkValue(v); err != nil {
			t.Errorf("checkValue(%q) = %v, want ok", v, err)
		}
	}
	bad := []string{"", ".", "..", "-x", "+x", "a/b", "a b", "a\tb", "a\nb", "a\x00", "é", "a\x7f"}
	for _, c := range "!\"#$%&'()*,;<>?[\\]^`{|}~" {
		bad = append(bad, "a"+string(c)+"b", string(c), "a"+string(c))
	}
	bad = append(bad, strings.Repeat("a", MaxValueLen+1))
	for _, v := range bad {
		if err := checkValue(v); err == nil {
			t.Errorf("checkValue(%q) = nil, want an error", v)
		}
	}
	// The error never quotes the value.
	if err := checkValue("SECRET$VALUE"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error = %v", err)
	}
}

func TestStrictClassInManifestAndArgs(t *testing.T) {
	// Enum members obey the class at manifest validation.
	for _, v := range []string{"a;b", "a$b", "a'b", `a"b`, "a,b", "a*b", "a|b", "a%b", "$(id)", "a~b", "a\\b"} {
		a := requeue()
		a.Params = append([]model.ActionParam(nil), a.Params...)
		a.Params[1].Enum = []string{"ok", v}
		if err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), "params.reason.enum:") {
			t.Errorf("enum value %q: got %v", v, err)
		}
	}
	// A pattern that could accept a character outside the class is refused.
	for _, p := range []string{
		`^[a-z$]+$`, `^a;b$`, `^[a-z']+$`, `^a,b$`, `^[!-9]+$`, `^a%b$`, `^[a-z~]+$`, `^[a-z*]+$`, `^a\|b$`,
		`^[a-z"]+$`, `^\$\(id\)$`, `^[a-z&]+$`, `^[ -~]+$`, `^[a-z<>]+$`, "^[a-z`]+$", `^[a-z\\]+$`, `^[a-z{}]+$`,
		`^[a-z()]+$`, `^[a-z!]+$`, `^[a-z#]+$`, `^[a-z?]+$`, `^[a-z\[\]]+$`, `^[a-z^]+$`,
	} {
		if err := ValidatePattern(p); err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want an error", p)
		}
	}
	for _, p := range []string{`^[A-Za-z0-9._:@=+-]{1,64}$`, `^[a-z]+@[a-z.]+:[0-9]{2,5}$`, `^k=[a-z]+\+[0-9]$`, `^\w+$`, `^\d+$`} {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want ok", p, err)
		}
	}
	// At run time, whatever the manifest says (a manifest that slipped
	// past review), for int, enum and string alike.
	a := model.Action{Name: "x", Params: []model.ActionParam{
		{Name: "n", Type: "int"},
		{Name: "e", Type: "enum", Enum: []string{"a;b", "ok"}},
		{Name: "s", Type: "string", Pattern: `^.*$`},
	}}
	ok := map[string]string{"n": "1", "e": "ok", "s": "fine"}
	for _, c := range []struct{ k, v string }{
		{"n", "1;id"}, {"n", "$1"}, {"e", "a;b"}, {"s", "a;b"}, {"s", "$(id)"}, {"s", "a'b"}, {"s", `a"b`},
		{"s", "a|b"}, {"s", "a&b"}, {"s", "a>b"}, {"s", "a*"}, {"s", "a,b"}, {"s", "a%b"}, {"s", "`id`"},
	} {
		m := map[string]string{}
		for k, v := range ok {
			m[k] = v
		}
		m[c.k] = c.v
		if err := ValidateArgs(a, m); err == nil || strings.Contains(err.Error(), c.v) {
			t.Errorf("ValidateArgs(%s=%q) = %v, want an error that does not quote the value", c.k, c.v, err)
		}
	}
}

// realLocksshMatch is lockssh's own Rule.Match (internal/command): tokens
// separated by spaces, the first one literal, a token with * ? or [ is a
// path.Match glob over one argument, any other token is compared as is.
func realLocksshMatch(rule string, argv []string) bool {
	tokens := strings.Fields(rule)
	if len(tokens) != len(argv) {
		return false
	}
	for i, tok := range tokens {
		if i == 0 || !strings.ContainsAny(tok, "*?[") {
			if tok != argv[i] {
				return false
			}
			continue
		}
		if ok, err := path.Match(tok, argv[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

func anyRule(rules []string, argv []string) bool {
	for _, r := range rules {
		if realLocksshMatch(r, argv) {
			return true
		}
	}
	return false
}

func strAction(pattern string) model.Action {
	return model.Action{
		Name: "act", Description: "d", Level: model.ActionAuto, Script: "s.sh",
		Params:    []model.ActionParam{{Name: "v", Type: "string", Pattern: pattern}},
		RateLimit: model.RateLimit{Count: 1, Window: time.Hour}, Timeout: time.Minute,
	}
}

func TestAllowRulesShapes(t *testing.T) {
	const pre = "/opt/dutydesk/bin/dutydesk-act act --v "
	cases := []struct {
		pattern string
		want    []string
	}{
		// A fixed shape is matched exactly, character by character.
		{`^doc-[0-9a-f]{4}$`, []string{pre + "doc-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]"}},
		{`^v[0-9]\.[0-9]$`, []string{pre + "v[0-9].[0-9]"}},
		{`^abc$`, []string{pre + "abc"}},
		// A bounded tail: one exact rule per length while that stays small.
		{`^doc-[0-9]{1,3}$`, []string{pre + "doc-[0-9]", pre + "doc-[0-9][0-9]", pre + "doc-[0-9][0-9][0-9]"}},
		{`^[a-c]{0,2}$`, []string{pre + "[a-c]", pre + "[a-c][a-c]"}},
		// Too many lengths: the fixed part, then "*".
		{`^doc-[0-9a-f]{8,32}$`, []string{pre + "doc-" + strings.Repeat("[0-9a-f]", 8) + "*"}},
		{`^job-[a-z]+$`, []string{pre + "job-[a-z]*"}},
		// A value never starts with "-" or "+": the first class drops them.
		{`^[a-z0-9_.-]{1,64}$`, []string{pre + `[.0-9_a-z]*`}},
		{`^[a-z+-]{2}$`, []string{pre + `[a-z][+\-a-z]`}},
		// Nothing can be derived: the safe class without "-" and "+", then "*".
		{`^(doc|job)-[0-9]+$`, []string{pre + "[.0-9:=@A-Z_a-z]*"}},
		{`^[a-z]*x$`, []string{pre + "[.0-9:=@A-Z_a-z]*"}},
	}
	for _, c := range cases {
		got, err := AllowRules(strAction(c.pattern), "/opt/dutydesk/bin")
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %q, %v\nwant %q", c.pattern, got, err, c.want)
		}
		for _, r := range got {
			for _, tok := range strings.Fields(r) {
				if _, err := path.Match(tok, ""); err != nil {
					t.Errorf("%s: token %q is a malformed glob", c.pattern, tok)
				}
				if len(tok) > 4096 {
					t.Errorf("%s: token longer than lockssh's 4096 bytes", c.pattern)
				}
			}
		}
	}
}

// Every value the launcher accepts matches a rule (no valid command is
// refused by lockssh), and an exact rule set matches nothing else.
func TestAllowRulesAgreeWithValidateArgs(t *testing.T) {
	alphabet := []string{"a", "c", "z", "0", "9", "-", "+", ".", "_", "x", "d", "o", "A", "=", ";", "$", "/", " ", "*", "'"}
	var candidates []string
	var gen func(prefix string, n int)
	gen = func(prefix string, n int) {
		if prefix != "" {
			candidates = append(candidates, prefix)
		}
		if n == 0 {
			return
		}
		for _, c := range alphabet {
			gen(prefix+c, n-1)
		}
	}
	gen("", 3)
	for _, p := range []struct {
		pattern string
		exact   bool // the rules are as strict as the pattern
	}{
		{`^[a-c]{1,3}$`, true}, {`^d[0-9]{0,2}$`, true}, {`^[a-z0-9_.-]{1,3}$`, true}, {`^do[c-d]$`, true},
		{`^[a-z+-]{2}$`, true}, {`^x-?[0-9]$`, false}, {`^(a|c)[0-9]*$`, false}, {`^[a-z]+(-[a-z]+)*$`, false},
		{`^[a-z0-9]{1,40}$`, false}, {`^\w+$`, false}, {`^[.=A]{1,2}x?$`, false}, {`^[0-9]*[a-z]$`, false},
	} {
		a := strAction(p.pattern)
		rules, err := AllowRules(a, "/opt/dutydesk/bin")
		if err != nil {
			t.Fatalf("%s: %v", p.pattern, err)
		}
		for _, v := range candidates {
			valid := ValidateArgs(a, map[string]string{"v": v}) == nil
			matched := anyRule(rules, CommandLine(a, "/opt/dutydesk/bin", map[string]string{"v": v}))
			if valid && !matched {
				t.Errorf("%s: valid value %q matches no rule %q", p.pattern, v, rules)
			}
			// "." and "..": harmless tokens the launcher refuses by itself.
			if p.exact && matched && !valid && v != "." && v != ".." {
				t.Errorf("%s: rules %q match the invalid value %q", p.pattern, rules, v)
			}
			// Whatever the pattern, a rule never lets an option or a path
			// separator through, nor a value starting outside the class.
			// (After a "*" a glob cannot say more: the launcher does.)
			if matched && (v[0] == '-' || v[0] == '+' || strings.Contains(v, "/") || !safeByte(v[0])) {
				t.Errorf("%s: rules %q match %q", p.pattern, rules, v)
			}
		}
	}
}

func TestAllowRulesEnum(t *testing.T) {
	enum := func(vals ...string) model.ActionParam { return model.ActionParam{Type: "enum", Enum: vals} }
	a := model.Action{
		Name: "act", Description: "d", Level: model.ActionAuto, Script: "s.sh",
		RateLimit: model.RateLimit{Count: 1, Window: time.Hour}, Timeout: time.Minute,
	}
	named := func(ps ...model.ActionParam) []model.ActionParam {
		for i := range ps {
			ps[i].Name = string(rune('a' + i))
		}
		return ps
	}
	const pre = "/opt/dutydesk/bin/dutydesk-act act"

	// One rule per value; the product of two enums, in manifest order.
	a.Params = named(enum("queued", "done"), model.ActionParam{Type: "int"}, enum("soft", "hard"))
	got, err := AllowRules(a, "/opt/dutydesk/bin")
	want := []string{
		pre + " --a queued --b [0-9]* --c soft", pre + " --a queued --b [0-9]* --c hard",
		pre + " --a done --b [0-9]* --c soft", pre + " --a done --b [0-9]* --c hard",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, %v\nwant %q", got, err, want)
	}

	// The product is capped: the enum that would exceed MaxRulesPerAction
	// falls back to its tightest single glob.
	a.Params = named(enum("a1", "a2", "a3", "a4"), enum("b1", "b2", "b3", "b4"), enum("east", "west", "eu-1"))
	got, err = AllowRules(a, "/opt/dutydesk/bin")
	if err != nil || len(got) != 16 || len(got) > MaxRulesPerAction {
		t.Fatalf("got %d rules, %v", len(got), err)
	}
	for _, r := range got {
		if !strings.HasSuffix(r, " --c [ew]*") {
			t.Errorf("rule %q: the third enum should be the glob of its first characters", r)
		}
	}
	if got[0] != pre+" --a a1 --b b1 --c [ew]*" || got[15] != pre+" --a a4 --b b4 --c [ew]*" {
		t.Errorf("rules = %q", got)
	}
	big := make([]string, 40)
	for i := range big {
		big[i] = "region-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	a.Params = named(enum(big...))
	if got, err := AllowRules(a, "/opt/dutydesk/bin"); err != nil || !reflect.DeepEqual(got, []string{pre + " --a region-[a-z]*"}) {
		t.Errorf("got %q, %v", got, err)
	}
	// Enums take the budget first, then the exact lengths of a string.
	a.Params = named(model.ActionParam{Type: "string", Pattern: `^[a-z]{1,8}$`}, enum("x", "y", "z"))
	got, err = AllowRules(a, "/opt/dutydesk/bin")
	if err != nil || len(got) != 3 || got[0] != pre+" --a [a-z]* --b x" {
		t.Errorf("got %q, %v", got, err)
	}
	a.Params = named(model.ActionParam{Type: "string", Pattern: `^[a-z]{1,5}$`}, enum("x", "y", "z"))
	got, err = AllowRules(a, "/opt/dutydesk/bin")
	if err != nil || len(got) != 15 || got[0] != pre+" --a [a-z] --b x" || got[14] != pre+" --a [a-z][a-z][a-z][a-z][a-z] --b z" {
		t.Errorf("got %q, %v", got, err)
	}
}

// Hostile argvs against the rules of the usual test action.
func TestAllowRulesRefuseShellSyntax(t *testing.T) {
	a := requeue()
	rules, err := AllowRules(a, "/opt/dutydesk/bin")
	if err != nil {
		t.Fatal(err)
	}
	argv := func(job, reason, tag string) []string {
		return []string{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", job, "--reason", reason, "--tag", tag}
	}
	if !anyRule(rules, argv("42", "worker-lost", "night_run.1")) {
		t.Fatalf("the valid command line matches no rule: %q", rules)
	}
	for _, bad := range [][]string{
		argv("42", "other", "t"), argv("42", "stalled;id", "t"), argv("42", "*", "t"), argv("42", "stalled", "-rf"),
		argv("42", "stalled", "+x"), argv("42", "stalled", "$(id)"), argv("42", "stalled", "'x"), argv("42", "stalled", "a/b"),
		argv("-1", "stalled", "t"), argv("x", "stalled", "t"), argv("42", "Stalled", "t"), argv("42", "stalled", ";id"),
	} {
		if anyRule(rules, bad) {
			t.Errorf("a rule of %q matches %q", rules, bad)
		}
	}
}

// Fix 18 (shared with the launcher): LoadAction never follows a link.
func TestLoadActionRefusesSymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "evil.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, ManifestName), []byte(goodManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	link := func(target, name string) {
		t.Helper()
		if err := os.RemoveAll(name); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()

	dir := writeAction(t, root, "script-link", goodManifest, 0o755)
	link(filepath.Join(outside, "evil.sh"), filepath.Join(dir, "run.sh"))
	if _, err := LoadAction(dir); err == nil || !strings.Contains(err.Error(), "script:") || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("script link: %v", err)
	}

	dir = writeAction(t, root, "manifest-link", goodManifest, 0o755)
	link(filepath.Join(outside, ManifestName), filepath.Join(dir, ManifestName))
	if _, err := LoadAction(dir); err == nil || !strings.Contains(err.Error(), ManifestName) || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("manifest link: %v", err)
	}

	real := writeAction(t, root, "real-action", goodManifest, 0o755)
	alias := filepath.Join(root, "alias-action")
	link(real, alias)
	if _, err := LoadAction(alias); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("directory link: %v", err)
	}
	if _, err := LoadCatalogue(root); err == nil || !strings.Contains(err.Error(), "alias-action") {
		t.Errorf("catalogue with a linked action: %v", err)
	}

	dir = writeAction(t, root, "script-dir", goodManifest, 0o755)
	os.Remove(filepath.Join(dir, "run.sh"))
	os.Mkdir(filepath.Join(dir, "run.sh"), 0o755)
	if _, err := LoadAction(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("script directory: %v", err)
	}
}
