package model

import "testing"

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain text\twith\nlines":   "plain text\twith\nlines",
		"a\x1b[31mb\x07c\x00d\x7fe": "a[31mbcde",
		"crlf\r\nlone\rend":         "crlf\nlone\nend",
		"c1 \u009b0m sep x y":       "c1 0m sepxy",
		"bidi ‮evil⁦x":              "bidi evilx",
		"bad utf8 \xff\xfe ok":      "bad utf8  ok",
		"é ✓ 日本":                    "é ✓ 日本",
	} {
		if got := CleanText(in); got != want {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := CleanLine("  two\n\nlines\tand \x1b[0m  spaces "); got != "two lines and [0m spaces" {
		t.Errorf("CleanLine = %q", got)
	}
}
