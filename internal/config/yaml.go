package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// duration is a Go duration string in YAML ("20m", "168h").
type duration time.Duration

func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration (want e.g. \"20m\")", n.Line, s)
	}
	*d = duration(v)
	return nil
}

// decodeStrict decodes exactly one YAML document; an unknown key is an error.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if err == io.EOF {
			return errors.New("empty document")
		}
		return errors.New(strings.Join(strings.Fields(strings.TrimPrefix(err.Error(), "yaml: ")), " "))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("more than one YAML document")
	}
	return nil
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

const idRule = "want lower-case letters, digits, \"-\" and \"_\""

// ParseSeverity maps low|medium|high|critical to a model.Severity.
func ParseSeverity(s string) (model.Severity, error) {
	switch s {
	case "low":
		return model.SevLow, nil
	case "medium":
		return model.SevMedium, nil
	case "high":
		return model.SevHigh, nil
	case "critical":
		return model.SevCritical, nil
	}
	return 0, fmt.Errorf("%q is not a severity (want low, medium, high or critical)", s)
}

// errlist collects every problem of a load, each prefixed by its file.
type errlist struct{ errs []error }

func (e *errlist) addf(file, format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf("%s: %s", file, fmt.Sprintf(format, args...)))
}

func (e *errlist) err() error { return errors.Join(e.errs...) }
