package forge

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBranchName(t *testing.T) {
	for _, tc := range []struct{ id, title, want string }{
		{"INC-000123", "Short slug", "dutydesk/inc-000123-short-slug"},
		{"INC-000123", "  Fix: the *stuck* job (again)!  ", "dutydesk/inc-000123-fix-the-stuck-job-again"},
		{"INC-000123", "", "dutydesk/inc-000123"},
		{"INC-000123", "éà!!", "dutydesk/inc-000123"},
		{"", "x", "dutydesk/inc-x"},
		{"INC-7", strings.Repeat("very long title ", 20), ""},
	} {
		got := BranchName(tc.id, tc.title)
		if tc.want != "" && got != tc.want {
			t.Errorf("BranchName(%q, %q) = %q, want %q", tc.id, tc.title, got, tc.want)
		}
		if !validBranch(got) || len(got) > 90 {
			t.Errorf("BranchName(%q, %q) = %q is not a valid branch", tc.id, tc.title, got)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"projects/*/project.yaml", "projects/shop/project.yaml", true},
		{"projects/*/project.yaml", "projects/shop/sub/project.yaml", false},
		{"projects/*/project.yaml", "projects/shop/project.yaml.bak", false},
		{"standard/security", "standard/security/rules.md", true},
		{"standard/security/", "standard/security", true},
		{"standard/security", "standard/securityx/rules.md", false},
		{"**/seats.yaml", "seats.yaml", true},
		{"**/seats.yaml", "a/b/seats.yaml", true},
		{"*.md", "a/b.md", false},
		{"*.md", "b.md", true},
		{"a/**/z", "a/z", true},
		{"a/**/z", "a/b/c/z", true},
		{"a/**", "a/b/c", true},
		{"a/**", "ab/c", false},
		{"/a/?.txt", "a/b.txt", true},
	} {
		if got := matchAny([]string{tc.pattern}, tc.name); got != tc.want {
			t.Errorf("match(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
	if err := (PathPolicy{Deny: []string{"a/[b"}}).validate(); err == nil {
		t.Error("bad pattern accepted")
	}
	if err := (PathPolicy{Allow: []string{"/"}}).validate(); err == nil {
		t.Error("empty pattern accepted")
	}
}

func TestLiteralSecretInBase64AtEveryAlignment(t *testing.T) {
	secret := "seat-token-abcdefghijklmnop"
	for _, prefix := range []string{"", "a", "ab", "abc", "user:"} {
		for _, suffix := range []string{"", "x", "xy", "\n"} {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
				s := newScanner([]string{secret})
				s.line("f", 1, []byte("v="+enc.EncodeToString([]byte(prefix+secret+suffix))))
				if len(s.findings) != 1 {
					t.Errorf("prefix %q suffix %q: not found", prefix, suffix)
				}
			}
		}
	}
	s := newScanner([]string{secret, "short", ""})
	s.line("f", 1, []byte("nothing short here, seat-token-abcdefghijklmno only"))
	if len(s.findings) != 0 {
		t.Errorf("false positive: %v", s.findings)
	}
}

func TestPatternsAvoidObviousFalsePositives(t *testing.T) {
	for _, l := range []string{
		`password = os.environ["DB_PASSWORD"]`,
		`password: "${DB_PASSWORD_FROM_VAULT}"`,
		`password := getPassword(ctx, user)`,
		`if password == "" {`,
		`the glpat- prefix and sk-ant- prefix are documented`,
		`AKIAIOSFODNN7EXAMPLEX is too long`,
		`-----BEGIN PUBLIC KEY-----`,
	} {
		s := newScanner(nil)
		s.line("f", 1, []byte(l))
		if len(s.findings) != 0 {
			t.Errorf("%q: %v", l, s.findings)
		}
	}
	for _, l := range []string{
		`DB_PASSWORD=Zx81kq0PlmW92nB7`,
		`  password: 'correct-horse-battery'`,
		`-----BEGIN RSA PRIVATE KEY-----`,
		`-----BEGIN PRIVATE KEY-----`,
		`github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz`,
	} {
		s := newScanner(nil)
		s.line("f", 1, []byte(l))
		if len(s.findings) != 1 {
			t.Errorf("%q not detected", l)
		}
	}
}

func TestSymlinkEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		{"a/link", "../b", false},
		{"a/link", "../../b", true},
		{"link", "..", true},
		{"link", "a/../../x", true},
		{"link", "/abs", true},
		{"a/b/link", "../../c/d", false},
		{"link", "", true},
	} {
		if got := symlinkEscapes(tc.name, tc.target); got != tc.want {
			t.Errorf("symlinkEscapes(%q, %q) = %v", tc.name, tc.target, got)
		}
	}
}
