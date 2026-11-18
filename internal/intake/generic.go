package intake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// generic extracts the fields the webhook's configuration names
// (output field -> dotted path into the payload) and nothing else. A path
// segment is an object key or, in an array, an index. Only strings,
// numbers and booleans are kept; a path that leads elsewhere gives no
// field.
//
// The values are as untrusted as Sentry's: a field is kept through
// mappedText, and the fingerprint (which is also the summary's variable
// part, so an alert's title) is rendered from the same values reduced to
// identifiers by ident.
func generic(body []byte, source string, wh model.Webhook) (delivery, error) {
	if wh.FingerprintTemplate == "" {
		return delivery{}, &configError{"the generic webhook has no fingerprint template"}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return delivery{}, errors.New("the body is not JSON")
	}
	fields := make(map[string]string, len(wh.Fields))
	ids := make(map[string]string, len(wh.Fields))
	for name, path := range wh.Fields {
		// An empty value is no value: it would give a fingerprint that
		// merges unrelated problems.
		if v, ok := lookup(payload, path); ok {
			if t := mappedText(v); t != "" {
				fields[name] = t
			}
			if id := ident(v); id != "" {
				ids[name] = id
			}
		}
	}
	fp, err := check.Render(wh.FingerprintTemplate, ids)
	if err != nil {
		var mf *check.MissingFieldError
		if errors.As(err, &mf) {
			return delivery{}, fmt.Errorf("the payload lacks the fingerprint field %q", mf.Field)
		}
		return delivery{}, err
	}
	return delivery{signal: &model.Signal{Fingerprint: fp, Summary: source + ": " + fp, Fields: fields}}, nil
}

// lookup follows a dotted path and returns the scalar it leads to.
func lookup(v any, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	for _, seg := range strings.Split(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return "", false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return "", false
			}
			v = node[i]
		default:
			return "", false
		}
	}
	switch s := v.(type) {
	case string:
		return s, true
	case json.Number:
		return s.String(), true
	case bool:
		return strconv.FormatBool(s), true
	}
	return "", false
}
