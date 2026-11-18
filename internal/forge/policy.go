package forge

import (
	"fmt"
	"path"
	"strings"
)

// PathPolicy restricts which paths a proposal may touch. Patterns are globs
// anchored at the repository root, with "/" separators: "*" and "?" stay
// inside one path segment, "**" spans any number of segments. A pattern that
// matches a directory matches everything below it.
//
// With a non-empty Allow, every changed path must match one Allow pattern.
// No changed path may match a Deny pattern.
//
// With NoSymlinks, no changed path may be a symbolic link, wherever it points.
type PathPolicy struct {
	Allow []string
	Deny  []string
	// NoSymlinks refuses every added or modified symbolic link (ErrForbiddenPath).
	NoSymlinks bool
}

func splitPattern(p string) []string {
	p = strings.TrimPrefix(p, "./")
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func (p PathPolicy) validate() error {
	for _, list := range [][]string{p.Allow, p.Deny} {
		for _, pat := range list {
			segs := splitPattern(pat)
			if len(segs) == 0 {
				return fmt.Errorf("forge: empty path pattern")
			}
			for _, s := range segs {
				if _, err := path.Match(s, ""); err != nil {
					return fmt.Errorf("forge: bad path pattern %q", pat)
				}
			}
		}
	}
	return nil
}

// violations returns the paths refused by the policy, in input order.
func (p PathPolicy) violations(paths []string) []string {
	var bad []string
	for _, name := range paths {
		if matchAny(p.Deny, name) || (len(p.Allow) > 0 && !matchAny(p.Allow, name)) {
			bad = append(bad, name)
		}
	}
	return bad
}

func matchAny(patterns []string, name string) bool {
	ns := strings.Split(name, "/")
	for _, pat := range patterns {
		if globMatch(splitPattern(pat), ns) {
			return true
		}
	}
	return false
}

func globMatch(ps, ns []string) bool {
	if len(ps) == 0 {
		return true // the pattern matched the path or one of its parent directories
	}
	if ps[0] == "**" {
		if len(ps) == 1 {
			return true
		}
		for i := 0; i <= len(ns); i++ {
			if globMatch(ps[1:], ns[i:]) {
				return true
			}
		}
		return false
	}
	if len(ns) == 0 {
		return false
	}
	ok, _ := path.Match(ps[0], ns[0])
	return ok && globMatch(ps[1:], ns[1:])
}
