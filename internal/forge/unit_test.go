package forge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func TestLiteralSecretReversedAndHex(t *testing.T) {
	secret := "seat-token-abcdefghijklmnop"
	rev := []byte(secret)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	low := hex.EncodeToString([]byte(secret))
	for name, l := range map[string]string{
		"reversed":  "v=" + string(rev) + ";",
		"hex lower": "v=" + low + ";",
		"hex upper": "v=0x" + strings.ToUpper(low) + ";",
	} {
		s := newScanner([]string{secret})
		s.line("f", 1, []byte(l))
		if len(s.findings) != 1 || !strings.Contains(s.findings[0], "known-secret") {
			t.Errorf("%s form not found: %v", name, s.findings)
		}
	}
	s := newScanner([]string{secret})
	s.line("f", 1, []byte("v="+low[:len(low)-2]+" and "+string(rev[1:])))
	if len(s.findings) != 0 {
		t.Errorf("false positive: %v", s.findings)
	}
}

func TestSymlinkEscapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		links map[string]string
		want  bool
	}{
		{"a/link", map[string]string{"a/link": "../b"}, false},
		{"a/link", map[string]string{"a/link": "../../b"}, true},
		{"link", map[string]string{"link": ".."}, true},
		{"link", map[string]string{"link": "a/../../x"}, true},
		{"link", map[string]string{"link": "/abs"}, true},
		{"a/b/link", map[string]string{"a/b/link": "../../c/d"}, false},
		{"link", map[string]string{"link": ""}, true},
		{"link", map[string]string{"link": "a\x00b"}, true},
		{"dir/link", map[string]string{"dir/link": "../other/file"}, false},
		// Chains.
		{"a", map[string]string{"a": "b", "b": "../../etc"}, true},
		{"a", map[string]string{"a": "b", "b": "/etc"}, true},
		{"a", map[string]string{"a": "b", "b": "c", "c": "src/x"}, false},
		{"a", map[string]string{"a": "d/e/f", "d": "x/y"}, false},
		// Lexically inside, outside once p/r is followed.
		{"p/q/l", map[string]string{"p/q/l": "../r/../../x"}, false},
		{"p/q/l", map[string]string{"p/q/l": "../r/../../x", "p/r": ".."}, true},
		{"l", map[string]string{"l": "deep/../../x", "deep": "a/b"}, false},
		// Loops and long chains cannot be resolved safely.
		{"a", map[string]string{"a": "b", "b": "a"}, true},
		{"a", map[string]string{"a": "a"}, true},
		{"a", map[string]string{"a": "a/x"}, true},
	} {
		if got, _ := symlinkEscapes(tc.links, tc.name); got != tc.want {
			t.Errorf("symlinkEscapes(%v, %q) = %v", tc.links, tc.name, got)
		}
	}
	long := map[string]string{}
	for i := 0; i < maxLinkHops+5; i++ {
		long[fmt.Sprintf("l%d", i)] = fmt.Sprintf("l%d", i+1)
	}
	if got, _ := symlinkEscapes(long, "l0"); !got {
		t.Error("a chain longer than the hop limit was accepted")
	}
	if got, _ := symlinkEscapes(long, fmt.Sprintf("l%d", maxLinkHops)); got {
		t.Error("a short chain was refused")
	}
	_, via := symlinkEscapes(map[string]string{"a": "b", "b": "c/d", "c": "x"}, "a")
	if strings.Join(via, " ") != "a b c" {
		t.Errorf("followed links: %v", via)
	}
}

func TestMeasureTree(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "big"), strings.Repeat("x", 5000))
	write(t, filepath.Join(root, "a.txt"), strings.Repeat("x", 100))
	write(t, filepath.Join(root, "d", "b.txt"), strings.Repeat("x", 100))
	write(t, filepath.Join(root, ".git", "objects", "pack"), strings.Repeat("x", 9000))
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "big"), filepath.Join(root, "bigl")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// 5 entries (a.txt, d, d/b.txt, out, bigl), 200 bytes: links are not followed, the top .git is not counted.
	if err := measureTree(ctx, root, 5, 200); err != nil {
		t.Fatalf("tree within the caps refused: %v", err)
	}
	if err := measureTree(ctx, root, 4, 200); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "MaxTreeFiles") {
		t.Fatalf("too many files: %v", err)
	}
	if err := measureTree(ctx, root, 5, 199); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "MaxTreeBytes") {
		t.Fatalf("too many bytes: %v", err)
	}
	// A nested .git is part of what git would walk.
	write(t, filepath.Join(root, "d", ".git", "x"), "x")
	if err := measureTree(ctx, root, 5, 200); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("nested .git not counted: %v", err)
	}
}
