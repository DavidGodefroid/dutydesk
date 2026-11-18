// Package actions holds everything about validated catalogue actions that
// is shared by the core, the config loader and the launcher installed on
// the action host: manifest loading, parameter validation, the exact
// command line of an action and the lockssh rules proposed for it.
package actions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const (
	// LauncherName is the binary installed on the action host.
	LauncherName = "dutydesk-act"
	// DefaultInstallDir is where the launcher binary lives on the action host.
	DefaultInstallDir = "/opt/dutydesk/bin"
	// DefaultCatalogueDir is where the validated actions are installed.
	DefaultCatalogueDir = "/opt/dutydesk/actions"
	// ManifestName is the manifest file inside an action directory.
	ManifestName = "action.yaml"
	// DefaultTimeout applies to a manifest without a timeout.
	DefaultTimeout = time.Minute
	// MaxTimeout is lockssh's request_timeout ceiling: a longer action
	// could never return its result through the lock.
	MaxTimeout = 10 * time.Minute
	// MaxValueLen bounds one parameter value, in bytes.
	MaxValueLen = 256
)

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	scriptRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// ValidName reports whether s is a legal action or parameter name:
// lower-case letters, digits and "-", starting with a letter.
func ValidName(s string) bool { return nameRe.MatchString(s) }

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

type manifestFile struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Level       string      `yaml:"level"`
	Script      string      `yaml:"script"`
	Params      []paramFile `yaml:"params"`
	RateLimit   struct {
		Count  int      `yaml:"count"`
		Window duration `yaml:"window"`
	} `yaml:"rate_limit"`
	Timeout duration `yaml:"timeout"`
}

type paramFile struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Pattern string   `yaml:"pattern"`
	Enum    []string `yaml:"enum"`
	Min     *int64   `yaml:"min"`
	Max     *int64   `yaml:"max"`
}

// LoadAction loads and validates one action directory (action.yaml next
// to its script). The action is named after the directory; a "name" key,
// when present, must agree. The directory, the manifest and the script are
// checked with Lstat: a symbolic link is refused. Errors name the manifest
// field.
func LoadAction(dir string) (model.Action, error) {
	name := filepath.Base(filepath.Clean(dir))
	// Lstat everywhere: neither the directory, the manifest nor the script
	// may be a symbolic link (or anything but a directory / regular file).
	if st, err := os.Lstat(dir); err != nil {
		return model.Action{}, err
	} else if st.Mode()&os.ModeSymlink != 0 {
		return model.Action{}, errors.New("the action directory is a symbolic link")
	} else if !st.IsDir() {
		return model.Action{}, errors.New("not a directory")
	}
	if st, err := os.Lstat(filepath.Join(dir, ManifestName)); err != nil {
		return model.Action{}, err
	} else if !st.Mode().IsRegular() {
		return model.Action{}, fmt.Errorf("%s: not a regular file (a symbolic link is refused)", ManifestName)
	}
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return model.Action{}, err
	}
	var mf manifestFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&mf); err != nil {
		if err == io.EOF {
			err = errors.New("empty manifest")
		}
		return model.Action{}, fmt.Errorf("%s: %s", ManifestName, strings.Join(strings.Fields(err.Error()), " "))
	}
	if mf.Name != "" && mf.Name != name {
		return model.Action{}, fmt.Errorf("%s: name: %q does not match the directory name %q", ManifestName, mf.Name, name)
	}
	a := model.Action{
		Name:        name,
		Description: mf.Description,
		Level:       model.ActionLevel(mf.Level),
		Script:      mf.Script,
		RateLimit:   model.RateLimit{Count: mf.RateLimit.Count, Window: time.Duration(mf.RateLimit.Window)},
		Timeout:     time.Duration(mf.Timeout),
	}
	if a.Timeout == 0 {
		a.Timeout = DefaultTimeout
	}
	for _, p := range mf.Params {
		a.Params = append(a.Params, model.ActionParam{
			Name: p.Name, Type: p.Type, Pattern: p.Pattern, Enum: p.Enum, Min: p.Min, Max: p.Max,
		})
	}
	if err := ValidateAction(a); err != nil {
		return model.Action{}, fmt.Errorf("%s: %w", ManifestName, err)
	}
	st, err := os.Lstat(filepath.Join(dir, a.Script))
	switch {
	case err != nil:
		return model.Action{}, fmt.Errorf("%s: script: %q not found in the action directory", ManifestName, a.Script)
	case !st.Mode().IsRegular():
		return model.Action{}, fmt.Errorf("%s: script: %q is not a regular file (a symbolic link is refused)", ManifestName, a.Script)
	case st.Mode().Perm()&0o111 == 0:
		return model.Action{}, fmt.Errorf("%s: script: %q is not executable", ManifestName, a.Script)
	}
	return a, nil
}

// LoadCatalogue loads every action directory under dir (actions/<name>/).
// A missing dir is an empty catalogue. Every invalid action is reported.
func LoadCatalogue(dir string) (map[string]model.Action, error) {
	out := map[string]model.Action{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var errs []error
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !e.IsDir() {
			errs = append(errs, fmt.Errorf("%s: unexpected file (want one directory per action)", e.Name()))
			continue
		}
		if !ValidName(e.Name()) {
			errs = append(errs, fmt.Errorf("%s: invalid action name (want lower-case letters, digits and \"-\", starting with a letter)", e.Name()))
			continue
		}
		a, err := LoadAction(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%w", e.Name(), err))
			continue
		}
		out[a.Name] = a
	}
	return out, errors.Join(errs...)
}

// ValidateAction checks a manifest. Errors start with the field name.
func ValidateAction(a model.Action) error {
	if !ValidName(a.Name) {
		return errors.New("name: want lower-case letters, digits and \"-\", starting with a letter")
	}
	if a.Description == "" {
		return errors.New("description: required")
	}
	if a.Level != model.ActionAuto && a.Level != model.ActionGreenLight {
		return fmt.Errorf("level: want %q or %q", model.ActionAuto, model.ActionGreenLight)
	}
	if !scriptRe.MatchString(a.Script) {
		return errors.New("script: want a plain file name inside the action directory")
	}
	if a.RateLimit.Count < 1 {
		return errors.New("rate_limit.count: required, at least 1 (every action is rate limited)")
	}
	if a.RateLimit.Count > 10000 {
		return errors.New("rate_limit.count: at most 10000")
	}
	if a.RateLimit.Window <= 0 {
		return errors.New("rate_limit.window: required, a positive duration")
	}
	if a.Timeout <= 0 || a.Timeout > MaxTimeout {
		return fmt.Errorf("timeout: want a duration in (0, %s]", MaxTimeout)
	}
	seen := map[string]bool{}
	for i, p := range a.Params {
		f := fmt.Sprintf("params[%d]", i)
		if !ValidName(p.Name) {
			return fmt.Errorf("%s.name: want lower-case letters, digits and \"-\", starting with a letter", f)
		}
		f = "params." + p.Name
		if seen[p.Name] {
			return fmt.Errorf("%s: declared twice", f)
		}
		seen[p.Name] = true
		switch p.Type {
		case "int":
			if p.Pattern != "" || len(p.Enum) > 0 {
				return fmt.Errorf("%s: an int takes only min and max", f)
			}
			if p.Min != nil && *p.Min < 0 {
				return fmt.Errorf("%s.min: negative values are not supported (a value never starts with \"-\")", f)
			}
			if p.Max != nil && (*p.Max < 0 || (p.Min != nil && *p.Max < *p.Min)) {
				return fmt.Errorf("%s.max: lower than min", f)
			}
		case "string":
			if len(p.Enum) > 0 || p.Min != nil || p.Max != nil {
				return fmt.Errorf("%s: a string takes only pattern", f)
			}
			if p.Pattern == "" {
				return fmt.Errorf("%s.pattern: required for a string", f)
			}
			if err := ValidatePattern(p.Pattern); err != nil {
				return fmt.Errorf("%s.pattern: %w", f, err)
			}
		case "enum":
			if p.Pattern != "" || p.Min != nil || p.Max != nil {
				return fmt.Errorf("%s: an enum takes only enum", f)
			}
			if len(p.Enum) == 0 {
				return fmt.Errorf("%s.enum: at least one value", f)
			}
			vals := map[string]bool{}
			for _, v := range p.Enum {
				if err := checkValue(v); err != nil {
					return fmt.Errorf("%s.enum: a value %w", f, err)
				}
				if vals[v] {
					return fmt.Errorf("%s.enum: a value is listed twice", f)
				}
				vals[v] = true
			}
		default:
			return fmt.Errorf("%s.type: want int, string or enum", f)
		}
	}
	return nil
}

// ValidatePattern enforces the rule for string parameter patterns, so that
// a pattern can provably never match a character outside SafeValueClass
// (no shell metacharacter, quote, "/", whitespace or control character):
//
//   - the pattern is anchored: it starts with ^ and ends with $, once, at
//     the top level (so "^a$|^b$" is refused; write "^(a|b)$");
//   - between the anchors, only literals, character classes, groups,
//     alternation and repetition (? * + {n,m});
//   - every literal and every character class holds only characters of
//     SafeValueClass. That refuses ".", negated classes, \s \S \D \W,
//     Unicode classes, and (?i) on a class with letters.
//
// The check walks the parsed expression, so escapes and ranges that hide
// another character ("[+-9]" holds "," and "/") are refused as well.
func ValidatePattern(pattern string) error {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("does not compile: %v", err)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("does not compile: %v", err)
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 3 ||
		re.Sub[0].Op != syntax.OpBeginText || re.Sub[len(re.Sub)-1].Op != syntax.OpEndText {
		return errors.New("must be anchored as ^...$ with a non-empty body")
	}
	for _, sub := range re.Sub[1 : len(re.Sub)-1] {
		if err := walkPattern(sub); err != nil {
			return err
		}
	}
	return nil
}

func safeRune(r rune) bool { return r >= 0 && r < 0x80 && safeByte(byte(r)) }

func walkPattern(re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !safeRune(r) {
				return errors.New("a literal may only hold characters of " + SafeValueClass)
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if lo < 0x21 || hi > 0x7E {
				return errors.New("a character class may only hold characters of " + SafeValueClass + " (no negated class, \\s, \\S, \\W, \\D)")
			}
			for r := lo; r <= hi; r++ {
				if !safeRune(r) {
					return errors.New("a character class may only hold characters of " + SafeValueClass + " (a range must not cross another character)")
				}
			}
		}
	case syntax.OpConcat, syntax.OpAlternate, syntax.OpCapture,
		syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		for _, sub := range re.Sub {
			if err := walkPattern(sub); err != nil {
				return err
			}
		}
	case syntax.OpEmptyMatch:
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return errors.New("the \".\" wildcard is not allowed; use a character class")
	default:
		return errors.New("only literals, character classes, groups and repetition are allowed between ^ and $")
	}
	return nil
}
