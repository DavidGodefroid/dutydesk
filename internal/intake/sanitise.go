package intake

import (
	"regexp"
	"strings"
)

// Everything a webhook says is written by whoever can make the monitored
// application fail: a culprit, a function or a file name is text an
// attacker chooses, and it ends up in an agent's prompt, in alerts and in
// a terminal. What is kept therefore goes through one of the filters
// below; nothing is kept as it came.

const (
	// maxText caps a free-text value.
	maxText = 120
	// maxIdent caps an identifier.
	maxIdent = 64
	// redacted stands for a part of a value that looked like the identity
	// of a person or of a record.
	redacted = "<id>"
)

// textRune reports whether c may stay in a free-text value: ASCII letters
// and digits and the punctuation that code locations are made of
// (namespaces, paths, methods, signatures).
//
// Left out on purpose: every quote and the backtick (they close a quoted or
// a code span in a prompt or a message), '<' '>' (markup, chat mentions),
// '[' ']' (the text half of a Markdown link, the start of a terminal
// escape), '{' '}' '$' (template and shell expansion), '*' '~' '|' '!' '='
// '&' ';' '%' '?' '^' '+', every control character and everything outside
// ASCII (look-alikes, bidirectional overrides, separators).
func textRune(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.ContainsRune(`_.:/\@#(),- `, c)
}

// filterText drops every character textRune refuses. White space becomes
// one space, so a value is always one line.
func filterText(s string) string {
	var b strings.Builder
	space := true // no leading space
	for _, c := range s {
		switch {
		case c == ' ' || c == '\n' || c == '\t' || c == '\r':
			if !space {
				b.WriteByte(' ')
			}
			space = true
		case textRune(c):
			b.WriteRune(c)
			space = false
		}
	}
	return strings.TrimRight(b.String(), " ")
}

var (
	emailLike = regexp.MustCompile(`[A-Za-z0-9_.#-]+@[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+`)
	digitsRun = regexp.MustCompile(`[0-9]{6,}`)
	uuidLike  = regexp.MustCompile(`[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}`)
)

// redact replaces by "<id>" each segment of a filtered text (what stands
// between '/', '\', ' ', ',', '(' and ')') that holds an e-mail address
// and, when ids is set, a run of six digits or more or a UUID: a culprit
// such as "/users/jane.doe@example.com/orders/1234567" names a person and
// an order, "/users/<id>/orders/<id>" names the code.
func redact(s string, ids bool) string {
	var b strings.Builder
	start := 0
	flush := func(end int) {
		seg := s[start:end]
		if emailLike.MatchString(seg) || ids && (digitsRun.MatchString(seg) || uuidLike.MatchString(seg)) {
			seg = redacted
		}
		b.WriteString(seg)
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/', '\\', ' ', ',', '(', ')':
			flush(i)
			b.WriteByte(s[i])
			start = i + 1
		}
	}
	flush(len(s))
	return b.String()
}

// cut caps a filtered (ASCII) text at maxText bytes. A "<id>" the cap
// falls into goes whole: '<' is in a value only as part of it.
func cut(s string) string {
	if len(s) > maxText {
		s = s[:maxText]
		if i := strings.LastIndexByte(s, '<'); i >= 0 && !strings.HasPrefix(s[i:], redacted) {
			s = s[:i]
		}
	}
	return strings.TrimRight(s, " ")
}

// freeText is the filter of a value the monitored application words
// (Sentry's culprit, exception type, file, module, function): the
// conservative character class, no personal or record identifier, at most
// maxText bytes, one line.
func freeText(s string) string { return cut(redact(filterText(s), true)) }

// mappedText is the filter of a value the configuration of a generic
// webhook maps: the same class and cap. Addresses are redacted; numbers
// are not, a mapped number being a measure or the identifier the operator
// asked for.
func mappedText(s string) string { return cut(redact(filterText(s), false)) }

func identRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// ident makes an identifier of a value that goes into a fingerprint (and
// so into a summary and an alert's title): letters, digits, '_', '-' and
// '.', every other character becoming '_' (dropping it would merge more
// unrelated values), at most maxIdent bytes. A value without a letter or
// a digit is no identifier: "".
func ident(s string) string {
	var b strings.Builder
	alnum := false
	for _, c := range strings.TrimSpace(s) {
		if b.Len() == maxIdent {
			break
		}
		switch {
		case c == '_' || c == '-' || c == '.':
			b.WriteRune(c)
		case identRune(c):
			b.WriteRune(c)
			alnum = true
		default:
			b.WriteByte('_')
		}
	}
	if !alnum {
		return ""
	}
	return b.String()
}

// strictIdent keeps s only when it is an identifier already (Sentry's
// short id, a project slug); anything else is not kept at all.
func strictIdent(s string) string {
	if s == "" || len(s) > maxIdent {
		return ""
	}
	for _, c := range s {
		if !identRune(c) || c == '.' {
			return ""
		}
	}
	return s
}

var timestampLike = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]{1,9})?)?(Z|[+-][0-9]{2}:?[0-9]{2})?$`)

// timestamp keeps s only when it is an ISO 8601 date and time.
func timestamp(s string) string {
	if !timestampLike.MatchString(s) {
		return ""
	}
	return s
}

// sentryLevel keeps a level only when it is one of Sentry's.
func sentryLevel(s string) string {
	switch s {
	case "fatal", "error", "warning", "info", "debug", "sample":
		return s
	}
	return ""
}
