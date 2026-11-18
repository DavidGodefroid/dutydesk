package actions

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Rule is one lockssh allow rule, for one action.
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
	Rules    []Rule   // sorted by action name
}

// Allow lists the allow rules, in order.
func (pr ProfileRules) Allow() []string {
	out := make([]string, len(pr.Rules))
	for i, r := range pr.Rules {
		out[i] = r.Allow
	}
	return out
}

// AllowRule is the lockssh allow rule of one action: the literal launcher
// path, the literal action name, then for each parameter in manifest order
// the literal --name and ONE glob token for its value ("[0-9]*" for an
// int, "*" otherwise). lockssh globs never match "/", an argument starting
// with "-" or "+", nor a "." / ".." segment; ValidateArgs refuses the same
// values, and the launcher re-validates types and bounds on the host.
func AllowRule(a model.Action, installDir string) (string, error) {
	if err := checkInstallDir(installDir); err != nil {
		return "", err
	}
	if err := ValidateAction(a); err != nil {
		return "", fmt.Errorf("action %s: %w", a.Name, err)
	}
	tokens := []string{filepath.Join(installDir, LauncherName), a.Name}
	for _, p := range a.Params {
		glob := "*"
		if p.Type == "int" {
			glob = "[0-9]*"
		}
		tokens = append(tokens, "--"+p.Name, glob)
	}
	return strings.Join(tokens, " "), nil
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
			allow, err := AllowRule(a, installDir)
			if err != nil {
				return nil, fmt.Errorf("runbook %s: %w", rb.ID, err)
			}
			rule := Rule{Action: name, Level: a.Level, Allow: allow}
			if a.Level == model.ActionAuto {
				auto.Rules = append(auto.Rules, rule)
			} else {
				ask.Rules = append(ask.Rules, rule)
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
		for _, r := range pr.Rules {
			fmt.Fprintf(&b, "#   %-12s %s\n", r.Level, r.Action)
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
