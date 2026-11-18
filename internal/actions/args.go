package actions

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// SafeValueClass is the only set of characters a parameter value may hold,
// whatever its type: no shell metacharacter, no quote, no whitespace, no
// "/" and nothing outside ASCII. Enum members and string patterns are held
// to it when a manifest is validated, every value again at run time.
const SafeValueClass = "[A-Za-z0-9._:@=+-]"

func safeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == ':' || c == '@' || c == '=' || c == '+' || c == '-'
}

// checkValue is the rule every parameter value obeys, whatever its type:
// 1 to MaxValueLen characters of SafeValueClass, not starting with "-" or
// "+" (an option), and neither "." nor "..". Even if a layer between the
// agent and the script handed the value to a shell, it could not be read
// as shell syntax. The error never quotes the value.
func checkValue(v string) error {
	switch {
	case v == "":
		return errors.New("is empty")
	case len(v) > MaxValueLen:
		return fmt.Errorf("is longer than %d bytes", MaxValueLen)
	case v[0] == '-' || v[0] == '+':
		return errors.New("starts with \"-\" or \"+\"")
	case v == "." || v == "..":
		return errors.New("is \".\" or \"..\"")
	}
	for i := 0; i < len(v); i++ {
		if !safeByte(v[i]) {
			return errors.New("holds a character outside " + SafeValueClass)
		}
	}
	return nil
}

var intRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

// ValidateArgs checks args against the manifest of a: every declared
// parameter is present, nothing else is, and each value has its type
// (int: plain non-negative decimal within min/max; enum: one of the
// values; string: full match of the pattern). A value only holds
// characters of SafeValueClass and never starts with "-" or "+", whatever
// the manifest says. Errors name the parameter and never quote the value.
func ValidateArgs(a model.Action, args map[string]string) error {
	declared := map[string]bool{}
	for _, p := range a.Params {
		declared[p.Name] = true
		v, ok := args[p.Name]
		if !ok {
			return fmt.Errorf("parameter --%s: missing", p.Name)
		}
		if err := checkValue(v); err != nil {
			return fmt.Errorf("parameter --%s: the value %w", p.Name, err)
		}
		switch p.Type {
		case "int":
			if !intRe.MatchString(v) {
				return fmt.Errorf("parameter --%s: want a plain non-negative integer", p.Name)
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("parameter --%s: want a plain non-negative integer", p.Name)
			}
			if p.Min != nil && n < *p.Min {
				return fmt.Errorf("parameter --%s: below the minimum %d", p.Name, *p.Min)
			}
			if p.Max != nil && n > *p.Max {
				return fmt.Errorf("parameter --%s: above the maximum %d", p.Name, *p.Max)
			}
		case "enum":
			found := false
			for _, e := range p.Enum {
				found = found || e == v
			}
			if !found {
				return fmt.Errorf("parameter --%s: not one of the allowed values %v", p.Name, p.Enum)
			}
		case "string":
			if err := ValidatePattern(p.Pattern); err != nil {
				return fmt.Errorf("parameter --%s: manifest pattern refused: %w", p.Name, err)
			}
			re, err := regexp.Compile(p.Pattern)
			if err != nil {
				return fmt.Errorf("parameter --%s: manifest pattern does not compile", p.Name)
			}
			if loc := re.FindStringIndex(v); loc == nil || loc[0] != 0 || loc[1] != len(v) {
				return fmt.Errorf("parameter --%s: does not match the pattern %s", p.Name, p.Pattern)
			}
		default:
			return fmt.Errorf("parameter --%s: manifest type is not int, string or enum", p.Name)
		}
	}
	for name := range args {
		if !declared[name] {
			if ValidName(name) {
				return fmt.Errorf("parameter --%s: not a parameter of action %s", name, a.Name)
			}
			return fmt.Errorf("an unknown parameter was given to action %s", a.Name)
		}
	}
	return nil
}

// CommandLine is the exact argv the agent runs on the action host:
// <installDir>/dutydesk-act <action> --param value ... in manifest order.
// It does not validate: call ValidateArgs first.
func CommandLine(a model.Action, installDir string, args map[string]string) []string {
	argv := []string{filepath.Join(installDir, LauncherName), a.Name}
	for _, p := range a.Params {
		argv = append(argv, "--"+p.Name, args[p.Name])
	}
	return argv
}
