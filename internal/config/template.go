package config

import (
	"fmt"
	"regexp"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Placeholders lists the {name} placeholders of a template, in order of
// first use. A brace that is not part of a {name} placeholder is an error:
// templates have no other syntax.
func Placeholders(tmpl string) ([]string, error) {
	if rest := placeholderRe.ReplaceAllString(tmpl, ""); strings.ContainsAny(rest, "{}") {
		return nil, fmt.Errorf("template %q: only {name} placeholders are allowed (letters, digits, \"_\")", tmpl)
	}
	var names []string
	seen := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(tmpl, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	return names, nil
}

// MissingFieldError says a template names a field its data does not hold.
type MissingFieldError struct {
	Template string
	Field    string
}

func (e *MissingFieldError) Error() string {
	return fmt.Sprintf("template %q: no field %q", e.Template, e.Field)
}

// Render replaces every {name} of tmpl by fields[name]. A placeholder
// without a field is a *MissingFieldError; values are inserted as they are.
func Render(tmpl string, fields map[string]string) (string, error) {
	names, err := Placeholders(tmpl)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if _, ok := fields[n]; !ok {
			return "", &MissingFieldError{Template: tmpl, Field: n}
		}
	}
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		return fields[m[1:len(m)-1]]
	}), nil
}

// Family is the template without its variable parts, used as the incident
// family: "stuck-job:{job_id}" gives "stuck-job:". Whitespace left around
// is trimmed and runs of spaces collapse to one.
func Family(tmpl string) string {
	return strings.Join(strings.Fields(placeholderRe.ReplaceAllString(tmpl, "")), " ")
}
