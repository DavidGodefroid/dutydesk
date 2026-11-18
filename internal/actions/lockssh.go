package actions

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp/syntax"
	"sort"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Rule is one lockssh allow rule, for one action. An action has one rule
// or several (one per enum value, see AllowRules).
type Rule struct {
	Action string
	Level  model.ActionLevel
	Allow  string // lockssh allow-rule syntax: argv tokens separated by spaces
}

// ProfileRules is what one lockssh profile must carry: the actions of one
// level of the runbook(s) that use this instance, and nothing else.
//
// lockssh (v0.2.0) decides "runs at once" or "ticket" per PROFILE, not per
// rule: [profiles.<name>.auto] run = "auto" | "ask". So a runbook has up to
// two profiles:
//
//   - Runbook.ActionInstance carries its auto-level actions, run = "auto":
//     an allow-listed command runs without a ticket;
//   - Runbook.AskInstance carries its green-light actions, run = "ask":
//     every command of the profile becomes a ticket a human decides.
//
// Exec is always false: a command outside the catalogue is refused
// (E_NOT_ALLOWED), it never becomes a ticket.
type ProfileRules struct {
	Instance string   // Runbook.ActionInstance or AskInstance, also the proposed profile name
	Runbooks []string // runbook ids served by this profile
	Run      string   // "auto" | "ask"
	Exec     bool     // always false
	Rules    []Rule   // sorted by action name; the rules of one action are adjacent
}

// Allow lists the allow rules, in order.
func (pr ProfileRules) Allow() []string {
	out := make([]string, len(pr.Rules))
	for i, r := range pr.Rules {
		out[i] = r.Allow
	}
	return out
}

// MaxRulesPerAction caps the allow rules generated for one action (the
// product of its enum values and of the exact lengths of its strings). A
// parameter that would exceed it falls back to its tightest single glob.
const MaxRulesPerAction = 16

// maxGlobLen bounds one generated glob token, far under lockssh's 4096
// bytes per token.
const maxGlobLen = 1024

// AllowRules are the lockssh allow rules of one action: the literal
// launcher path, the literal action name, then for each parameter in
// manifest order the literal --name and ONE token for its value. lockssh
// matches a token with "*", "?" or "[" as a path.Match glob over one
// argument and any other token literally, so the value token is:
//
//   - int: "[0-9]*";
//   - enum: the value itself, one rule per value (the product over several
//     enums, in manifest order) while the action stays within
//     MaxRulesPerAction; an enum that does not fit becomes the common
//     prefix of its values, the class of the characters that follow, "*";
//   - string: what its pattern allows, as far as a glob can say it. A
//     fixed shape ("^doc-[0-9a-f]{8}$") is matched character by character;
//     a shape ending with a bounded repetition gets one exact rule per
//     length while that fits the budget left by the enums; otherwise the
//     fixed leading part followed by "*". When nothing can be derived the
//     token is the class of a first character followed by "*".
//
// A glob has no "one or more of this class": after "*" the remaining
// characters are only bounded by "/" at lockssh, and by the launcher,
// which re-validates every value (class, type, bounds, pattern) on the
// host. No token ever matches a value starting with "-" or "+".
func AllowRules(a model.Action, installDir string) ([]string, error) {
	if err := checkInstallDir(installDir); err != nil {
		return nil, err
	}
	if err := ValidateAction(a); err != nil {
		return nil, fmt.Errorf("action %s: %w", a.Name, err)
	}
	// Per parameter: the exact tokens (nil: none) and the single loose one.
	exact := make([][]string, len(a.Params))
	loose := make([]string, len(a.Params))
	for i, p := range a.Params {
		switch p.Type {
		case "int":
			loose[i] = "[0-9]*"
		case "enum":
			exact[i], loose[i] = p.Enum, enumGlob(p.Enum)
		default:
			exact[i], loose[i] = patternGlobs(p.Pattern)
		}
	}
	// Enums take the budget first, then strings, each in manifest order.
	choice := make([][]string, len(a.Params))
	n := 1
	for _, typ := range []string{"enum", "string"} {
		for i, p := range a.Params {
			if p.Type != typ {
				continue
			}
			if len(exact[i]) > 0 && n*len(exact[i]) <= MaxRulesPerAction {
				choice[i] = exact[i]
				n *= len(exact[i])
			}
		}
	}
	rules := []string{filepath.Join(installDir, LauncherName) + " " + a.Name}
	for i, p := range a.Params {
		tokens := choice[i]
		if tokens == nil {
			tokens = []string{loose[i]}
		}
		next := make([]string, 0, len(rules)*len(tokens))
		for _, r := range rules {
			for _, t := range tokens {
				next = append(next, r+" --"+p.Name+" "+t)
			}
		}
		rules = next
	}
	return rules, nil
}

// byteSet is a set of characters of SafeValueClass.
type byteSet [128]bool

func (s *byteSet) count() (n int) {
	for _, in := range s {
		if in {
			n++
		}
	}
	return n
}

// firstCharSet is what a value may start with: the safe class without
// "-" and "+".
func firstCharSet() *byteSet {
	var s byteSet
	for c := byte(0); c < 128; c++ {
		s[c] = safeByte(c) && c != '-' && c != '+'
	}
	return &s
}

// globAtom renders the set as one glob element: the character itself, or
// a class. No character of SafeValueClass is special outside a class;
// inside one only "-" is, and it is escaped.
func globAtom(s *byteSet) string {
	var b strings.Builder
	single := s.count() == 1
	if !single {
		b.WriteByte('[')
	}
	for c := 0; c < 128; c++ {
		if !s[c] {
			continue
		}
		end := c
		for alnum(byte(c)) && end+1 < 128 && s[end+1] && alnum(byte(end+1)) {
			end++
		}
		switch {
		case end-c >= 2:
			b.WriteByte(byte(c))
			b.WriteByte('-')
			b.WriteByte(byte(end))
			c = end
		case c == '-' && !single:
			b.WriteString(`\-`)
		default:
			b.WriteByte(byte(c))
		}
	}
	if !single {
		b.WriteByte(']')
	}
	return b.String()
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// renderGlob renders a sequence of sets. In first position "-" and "+" are
// dropped from a class: a value never starts with them.
func renderGlob(sets []*byteSet) string {
	var b strings.Builder
	for i, s := range sets {
		if i == 0 && (s['-'] || s['+']) {
			t := *s
			t['-'], t['+'] = false, false
			if t.count() > 0 {
				s = &t
			}
		}
		b.WriteString(globAtom(s))
	}
	return b.String()
}

// enumGlob is the tightest single glob over the values of an enum: their
// common prefix, the class of the characters that follow it, then "*".
func enumGlob(values []string) string {
	prefix := values[0]
	for _, v := range values[1:] {
		for !strings.HasPrefix(v, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	var sets []*byteSet
	for i := 0; i < len(prefix); i++ {
		var s byteSet
		s[prefix[i]] = true
		sets = append(sets, &s)
	}
	var next byteSet
	for _, v := range values {
		if len(v) == len(prefix) {
			// One value is the prefix itself: nothing has to follow it.
			next = byteSet{}
			break
		}
		next[v[len(prefix)]] = true
	}
	if next.count() > 0 {
		sets = append(sets, &next)
	}
	if len(sets) == 0 {
		sets = append(sets, firstCharSet())
	}
	return renderGlob(sets) + "*"
}

// patternGlobs turns a validated string pattern into glob tokens: exact is
// the complete list of globs matching exactly the shapes the pattern
// allows (nil when a glob cannot say it, or not within MaxRulesPerAction);
// loose is one glob matching at least every value the pattern allows.
func patternGlobs(pattern string) (exact []string, loose string) {
	generic := renderGlob([]*byteSet{firstCharSet()}) + "*"
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat || len(re.Sub) < 3 {
		return nil, generic
	}
	var (
		sets  []*byteSet // the fixed leading part
		size  int        // its rendered length, bounded by maxGlobLen
		open  bool       // something follows that a glob cannot say
		tail  *byteSet   // a final bounded repetition of one set...
		extra int        // ...0 to extra more times
	)
	push := func(s *byteSet) bool {
		if n := len(globAtom(s)); size+n <= maxGlobLen {
			sets, size = append(sets, s), size+n
			return true
		}
		open = true
		return false
	}
	// single is the set of a one-character expression, or nil.
	single := func(e *syntax.Regexp) *byteSet {
		for e.Op == syntax.OpCapture {
			e = e.Sub[0]
		}
		var s byteSet
		switch {
		case e.Op == syntax.OpLiteral && len(e.Rune) == 1 && e.Flags&syntax.FoldCase == 0 && safeRune(e.Rune[0]):
			s[e.Rune[0]] = true
		case e.Op == syntax.OpCharClass:
			for i := 0; i+1 < len(e.Rune); i += 2 {
				for r := e.Rune[i]; r <= e.Rune[i+1]; r++ {
					if !safeRune(r) {
						return nil
					}
					s[r] = true
				}
			}
		default:
			return nil
		}
		if s.count() == 0 {
			return nil
		}
		return &s
	}
	// emit appends e to the fixed part; false once the glob is open.
	var emit func(e *syntax.Regexp, last bool) bool
	emit = func(e *syntax.Regexp, last bool) bool {
		switch e.Op {
		case syntax.OpEmptyMatch:
			return true
		case syntax.OpCapture:
			return emit(e.Sub[0], last)
		case syntax.OpConcat:
			for i, sub := range e.Sub {
				if !emit(sub, last && i == len(e.Sub)-1) {
					return false
				}
			}
			return true
		case syntax.OpLiteral:
			if e.Flags&syntax.FoldCase != 0 {
				open = true
				return false
			}
			for _, r := range e.Rune {
				if !safeRune(r) {
					open = true
					return false
				}
				var s byteSet
				s[r] = true
				if !push(&s) {
					return false
				}
			}
			return true
		case syntax.OpCharClass:
			if s := single(e); s != nil {
				return push(s)
			}
		case syntax.OpRepeat, syntax.OpPlus, syntax.OpStar, syntax.OpQuest:
			lo, hi := e.Min, e.Max
			switch e.Op {
			case syntax.OpPlus:
				lo, hi = 1, -1
			case syntax.OpStar:
				lo, hi = 0, -1
			case syntax.OpQuest:
				lo, hi = 0, 1
			}
			s := single(e.Sub[0])
			if s == nil {
				break
			}
			for i := 0; i < lo; i++ {
				if !push(s) {
					return false
				}
			}
			switch {
			case hi == lo:
				return true
			case last && hi > lo:
				tail, extra = s, hi-lo
				return true
			}
		}
		open = true
		return false
	}
	body := re.Sub[1 : len(re.Sub)-1]
	for i, sub := range body {
		if !emit(sub, i == len(body)-1) {
			break
		}
	}
	switch {
	case len(sets) == 0 && (open || tail != nil && extra+1 > MaxRulesPerAction):
		return nil, generic
	case open:
		return nil, renderGlob(sets) + "*"
	case len(sets) == 0 && tail == nil:
		return nil, generic
	case tail == nil:
		g := renderGlob(sets)
		return []string{g}, g
	}
	loose = renderGlob(sets) + "*"
	if len(sets) == 0 {
		loose = generic
	}
	if extra+1 > MaxRulesPerAction || size+extra*len(globAtom(tail)) > maxGlobLen {
		return nil, loose
	}
	all := sets
	for k := 0; k <= extra; k++ {
		if len(all) > 0 { // the empty value is never valid
			exact = append(exact, renderGlob(all))
		}
		all = append(all[:len(all):len(all)], tail)
	}
	return exact, loose
}

// checkInstallDir: the program token of a rule is literal, tokens are
// separated by spaces, so the path may hold neither whitespace nor glob
// or quoting characters.
func checkInstallDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("install dir: want a clean absolute path")
	}
	for _, r := range dir {
		if r <= 0x20 || r > 0x7E || strings.ContainsRune(`*?[]\"'`, r) {
			return errors.New("install dir: whitespace, glob and quoting characters are not allowed")
		}
	}
	return nil
}

// LockSSHRules returns the rules of every lockssh profile the runbooks of p
// need, keyed by instance: the auto actions of a runbook under its
// ActionInstance (run "auto"), its green-light actions under its AskInstance
// (run "ask"). Runbooks that share an instance must give it the same
// actions, and an instance is never auto for one runbook and ask for
// another.
func LockSSHRules(p *model.Project, installDir string) (map[string]ProfileRules, error) {
	if err := checkInstallDir(installDir); err != nil {
		return nil, err
	}
	out := map[string]ProfileRules{}
	for _, rb := range p.Runbooks {
		if len(rb.Actions) == 0 {
			continue
		}
		names := append([]string(nil), rb.Actions...)
		sort.Strings(names)
		auto := ProfileRules{Instance: rb.ActionInstance, Runbooks: []string{rb.ID}, Run: "auto"}
		ask := ProfileRules{Instance: rb.AskInstance, Runbooks: []string{rb.ID}, Run: "ask"}
		for i, name := range names {
			if i > 0 && names[i-1] == name {
				return nil, fmt.Errorf("runbook %s: action %s is listed twice", rb.ID, name)
			}
			a, ok := p.Actions[name]
			if !ok {
				return nil, fmt.Errorf("runbook %s: action %s is not in the catalogue of project %s", rb.ID, name, p.Slug)
			}
			allow, err := AllowRules(a, installDir)
			if err != nil {
				return nil, fmt.Errorf("runbook %s: %w", rb.ID, err)
			}
			for _, al := range allow {
				rule := Rule{Action: name, Level: a.Level, Allow: al}
				if a.Level == model.ActionAuto {
					auto.Rules = append(auto.Rules, rule)
				} else {
					ask.Rules = append(ask.Rules, rule)
				}
			}
		}
		if rb.ActionInstance != "" && rb.ActionInstance == rb.AskInstance {
			return nil, fmt.Errorf("runbook %s: action_instance and ask_instance must differ", rb.ID)
		}
		for _, pr := range []ProfileRules{auto, ask} {
			key := "action_instance"
			if pr.Run == "ask" {
				key = "ask_instance"
			}
			if len(pr.Rules) == 0 {
				if pr.Instance != "" {
					return nil, fmt.Errorf("runbook %s: %s is set but the runbook has no such action", rb.ID, key)
				}
				continue
			}
			if pr.Instance == "" {
				return nil, fmt.Errorf("runbook %s: has %s actions but no %s", rb.ID, pr.Rules[0].Level, key)
			}
			prev, ok := out[pr.Instance]
			if !ok {
				out[pr.Instance] = pr
				continue
			}
			if prev.Run != pr.Run {
				return nil, fmt.Errorf("runbook %s: %s %s is the %s instance of runbook %s (a profile is auto or ask as a whole)",
					rb.ID, key, pr.Instance, prev.Run, prev.Runbooks[0])
			}
			if strings.Join(prev.Allow(), "\n") != strings.Join(pr.Allow(), "\n") {
				return nil, fmt.Errorf("runbook %s: %s %s is shared with runbook %s but the actions differ",
					rb.ID, key, pr.Instance, prev.Runbooks[0])
			}
			prev.Runbooks = append(prev.Runbooks, rb.ID)
			out[pr.Instance] = prev
		}
	}
	return out, nil
}

// RenderTOML renders the proposed rules as the lockssh config fragment a
// human reviews and merges into .lockssh/config.toml (host, user and key
// of each profile are his). Profiles are sorted by name.
func RenderTOML(project string, rules map[string]ProfileRules) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DutyDesk: proposed lockssh rules for project %s.\n", project)
	b.WriteString("# Generated from the action manifests. A new rule loosens the policy:\n")
	b.WriteString("# review it, then approve it in the lockssh console (:review).\n")
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pr := rules[k]
		fmt.Fprintf(&b, "\n# runbook: %s\n", strings.Join(pr.Runbooks, ", "))
		for i, r := range pr.Rules {
			if i == 0 || pr.Rules[i-1].Action != r.Action { // an action may have several rules
				fmt.Fprintf(&b, "#   %-12s %s\n", r.Level, r.Action)
			}
		}
		if pr.Run == "ask" {
			b.WriteString("# green-light: every command is a ticket decided by a human.\n")
		} else {
			b.WriteString("# auto: an allow-listed command runs without a ticket.\n")
		}
		fmt.Fprintf(&b, "[profiles.%s]\n", tomlKey(pr.Instance))
		b.WriteString("exec  = false\n")
		b.WriteString("allow = [\n")
		for _, r := range pr.Rules {
			fmt.Fprintf(&b, "  %s,\n", tomlString(r.Allow))
		}
		b.WriteString("]\n\n")
		fmt.Fprintf(&b, "[profiles.%s.auto]\n", tomlKey(pr.Instance))
		fmt.Fprintf(&b, "run  = %s\n", tomlString(pr.Run))
		b.WriteString("exec = \"deny\"\n")
	}
	return b.String()
}

func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func tomlKey(s string) string {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return tomlString(s)
		}
	}
	if s == "" {
		return `""`
	}
	return s
}
