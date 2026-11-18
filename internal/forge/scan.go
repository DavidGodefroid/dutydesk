package forge

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// minSecretLen is the shortest literal secret the scan looks for; shorter
// values would match ordinary text.
const minSecretLen = 8

const maxFindings = 20

type pattern struct {
	rule string
	re   *regexp.Regexp
	keep func(groups [][]byte) bool // optional extra condition
}

var builtinPatterns = []pattern{
	{rule: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY`)},
	{rule: "anthropic-token", re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{rule: "gitlab-token", re: regexp.MustCompile(`glpat-[A-Za-z0-9_.-]{20,}`)},
	{rule: "github-token", re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`)},
	{rule: "aws-access-key-id", re: regexp.MustCompile(`(?:^|[^A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?:[^A-Z0-9]|$)`)},
	{
		rule: "password-literal",
		re:   regexp.MustCompile(`(?i)(?:password|passwd|pwd)["']?\s*(?::=|[:=])\s*["']([^"'\s]{12,})["']`),
		keep: func(g [][]byte) bool {
			for _, p := range []string{"${", "$(", "{{", "<", "%"} {
				if bytes.HasPrefix(g[1], []byte(p)) {
					return false // a placeholder, not a literal
				}
			}
			return true
		},
	},
	{
		rule: "password-literal",
		re:   regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*([A-Za-z0-9+/=_!@#^&*-]{16,})\s*$`),
		keep: func(g [][]byte) bool {
			return bytes.ContainsAny(g[1], "0123456789") &&
				bytes.ContainsAny(g[1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		},
	},
}

// scanner looks for literal secrets (and their encoded forms) and for the
// built-in patterns. It reports where, never what.
type scanner struct {
	needles  [][]byte
	findings []string
}

func newScanner(secrets []string) *scanner {
	s := &scanner{}
	seen := map[string]bool{}
	for _, sec := range secrets {
		sec = strings.TrimSpace(sec)
		if len(sec) < minSecretLen {
			continue
		}
		for _, form := range secretForms([]byte(sec)) {
			if !seen[string(form)] {
				seen[string(form)] = true
				s.needles = append(s.needles, form)
			}
		}
	}
	return s
}

// secretForms returns the secret, the secret reversed, its hexadecimal form in
// lower and upper case, and the base64 strings that contain it at each of the
// three byte alignments, in both alphabets, without the edge characters that
// depend on neighbouring bytes. It is a best-effort list, not an exhaustive one.
func secretForms(sec []byte) [][]byte {
	rev := make([]byte, len(sec))
	for i, b := range sec {
		rev[len(sec)-1-i] = b
	}
	low := []byte(hex.EncodeToString(sec))
	forms := [][]byte{sec, rev, low, bytes.ToUpper(low)}
	skip := [3]int{0, 2, 3}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for off := 0; off < 3; off++ {
			padded := append(make([]byte, off), sec...)
			e := []byte(enc.EncodeToString(padded))
			if len(padded)%3 != 0 {
				e = e[:len(e)-1]
			}
			e = e[skip[off]:]
			if len(e) >= minSecretLen {
				forms = append(forms, e)
			}
		}
	}
	return forms
}

// ctContains reports whether needle occurs in hay, comparing every window in
// constant time and without stopping at the first match.
func ctContains(hay, needle []byte) bool {
	n := len(needle)
	if n == 0 || len(hay) < n {
		return false
	}
	found := 0
	for i := 0; i+n <= len(hay); i++ {
		found |= subtle.ConstantTimeCompare(hay[i:i+n], needle)
	}
	return found == 1
}

// line scans one line and records a finding "<where>:<line> (<rule>)".
func (s *scanner) line(where string, n int, text []byte) {
	if len(s.findings) >= maxFindings {
		return
	}
	hit := 0
	for _, needle := range s.needles {
		if ctContains(text, needle) {
			hit = 1
		}
	}
	if hit == 1 {
		s.findings = append(s.findings, fmt.Sprintf("%s:%d (known-secret)", where, n))
		return
	}
	for _, p := range builtinPatterns {
		g := p.re.FindSubmatch(text)
		if g == nil || (p.keep != nil && !p.keep(g)) {
			continue
		}
		s.findings = append(s.findings, fmt.Sprintf("%s:%d (%s)", where, n, p.rule))
		return
	}
}

// text scans a multi-line value such as the title or the description.
func (s *scanner) text(where, value string) {
	for i, l := range strings.Split(value, "\n") {
		s.line(where, i+1, []byte(l))
	}
}

// diff scans the added lines of a unified diff of one file.
func (s *scanner) diff(where string, patch []byte) {
	inHunk := false
	n := 0
	for len(patch) > 0 {
		var l []byte
		if i := bytes.IndexByte(patch, '\n'); i >= 0 {
			l, patch = patch[:i], patch[i+1:]
		} else {
			l, patch = patch, nil
		}
		switch {
		case bytes.HasPrefix(l, []byte("diff --git ")):
			inHunk = false
		case bytes.HasPrefix(l, []byte("@@ ")):
			inHunk = true
			n = hunkStart(l)
		case inHunk && bytes.HasPrefix(l, []byte("+")):
			s.line(where, n, l[1:])
			n++
		case inHunk && bytes.HasPrefix(l, []byte(" ")):
			n++
		}
	}
}

// hunkStart returns the first new-side line number of "@@ -a,b +c,d @@".
func hunkStart(l []byte) int {
	i := bytes.Index(l, []byte(" +"))
	if i < 0 {
		return 0
	}
	n := 0
	for _, c := range l[i+2:] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
