package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const strManifest = `description: Echo
level: auto
script: run.sh
params:
  - name: tag
    type: string
    pattern: "^[A-Za-z0-9._:@=+-]{1,40}$"
rate_limit: {count: 99, window: 1h}
`

// S3: only [A-Za-z0-9._:@=+-] reaches a script.
func TestStrictValueClass(t *testing.T) {
	h := newHost(t)
	marker := filepath.Join(h.root, "ran")
	h.install("echo-tag", strManifest, "#!/bin/sh\ntouch "+marker+"\nprintf '%s\\n' \"$2\"\n")
	if code, out, errb := h.run("echo-tag", "--tag", "user@db-1.internal:5432=a+b_c"); code != 0 || out != "user@db-1.internal:5432=a+b_c\n" {
		t.Fatalf("code %d, stdout %q, stderr %q", code, out, errb)
	}
	os.Remove(marker)
	for _, v := range []string{
		"$(id)", "a;id", "a|b", "a&b", "a>b", "a<b", "a*", "a?", "a'b", `a"b`, "a`id`", `a\b`, "a b", "a\tb", "a\nb",
		"a,b", "a%b", "a~b", "a#b", "a!b", "a{b}", "a(b)", "a[b]", "a^b", "a/b", "-x", "+x", "é", "$HOME", "",
	} {
		code, out, errb := h.run("echo-tag", "--tag", v)
		if code != exitUsage || out != "" {
			t.Errorf("%q: code %d, stdout %q, stderr %q; want exit 64", v, code, out, errb)
		}
		if v != "" && strings.Contains(errb, v) {
			t.Errorf("%q: the refused value is quoted on stderr: %q", v, errb)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the script ran on a refused value")
	}
}

func symlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.RemoveAll(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// Fix 18: the launcher only runs regular files of a real directory.
func TestRefusesLinksAndSpecialFiles(t *testing.T) {
	argv := []string{"requeue-job", "--job-id", "7", "--mode", "hard"}
	setup := func(t *testing.T) (h *host, marker, evil string) {
		h = newHost(t)
		marker = filepath.Join(h.root, "ran")
		body := "#!/bin/sh\ntouch " + marker + "\n"
		h.install("requeue-job", manifest(5, "1h", "10s"), body)
		evil = filepath.Join(h.root, "evil")
		if err := os.MkdirAll(evil, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(evil, "run.sh"), []byte(body), 0o755)
		os.WriteFile(filepath.Join(evil, "action.yaml"), []byte(manifest(5, "1h", "10s")), 0o644)
		return h, marker, evil
	}
	// The plain installation runs.
	h, marker, _ := setup(t)
	if code, _, errb := h.run(argv...); code != 0 {
		t.Fatalf("code %d, stderr %q", code, errb)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the script did not run")
	}

	cases := []struct {
		name string
		mut  func(t *testing.T, h *host, evil string)
	}{
		{"script is a link", func(t *testing.T, h *host, evil string) {
			symlink(t, filepath.Join(evil, "run.sh"), filepath.Join(h.actions, "requeue-job", "run.sh"))
		}},
		{"script is a link inside the action", func(t *testing.T, h *host, evil string) {
			dir := filepath.Join(h.actions, "requeue-job")
			os.Rename(filepath.Join(dir, "run.sh"), filepath.Join(dir, "real.sh"))
			symlink(t, "real.sh", filepath.Join(dir, "run.sh"))
		}},
		{"manifest is a link", func(t *testing.T, h *host, evil string) {
			symlink(t, filepath.Join(evil, "action.yaml"), filepath.Join(h.actions, "requeue-job", "action.yaml"))
		}},
		{"action directory is a link", func(t *testing.T, h *host, evil string) {
			symlink(t, evil, filepath.Join(h.actions, "requeue-job"))
		}},
		{"catalogue is a link", func(t *testing.T, h *host, evil string) {
			real := filepath.Join(h.root, "real-actions")
			if err := os.Rename(h.actions, real); err != nil {
				t.Fatal(err)
			}
			symlink(t, real, h.actions)
		}},
		{"script is a directory", func(t *testing.T, h *host, evil string) {
			p := filepath.Join(h.actions, "requeue-job", "run.sh")
			os.Remove(p)
			os.Mkdir(p, 0o755)
		}},
		{"script is a fifo", func(t *testing.T, h *host, evil string) {
			p := filepath.Join(h.actions, "requeue-job", "run.sh")
			os.Remove(p)
			if err := syscall.Mkfifo(p, 0o755); err != nil {
				t.Skip(err)
			}
		}},
		{"manifest is a fifo", func(t *testing.T, h *host, evil string) {
			p := filepath.Join(h.actions, "requeue-job", "action.yaml")
			os.Remove(p)
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Skip(err)
			}
		}},
		{"manifest is a directory", func(t *testing.T, h *host, evil string) {
			p := filepath.Join(h.actions, "requeue-job", "action.yaml")
			os.Remove(p)
			os.Mkdir(p, 0o755)
		}},
		{"action directory is a file", func(t *testing.T, h *host, evil string) {
			p := filepath.Join(h.actions, "requeue-job")
			os.RemoveAll(p)
			os.WriteFile(p, []byte("x"), 0o755)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, marker, evil := setup(t)
			c.mut(t, h, evil)
			code, out, errb := h.run(argv...)
			if code != exitInternal || out != "" || !strings.HasPrefix(errb, "dutydesk-act: ") {
				t.Errorf("code %d, stdout %q, stderr %q; want exit 70", code, out, errb)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("the script ran")
			}
			if recs := h.auditLines(); len(recs) != 1 || recs[0].Outcome != "error" || recs[0].Args != nil {
				t.Errorf("audit = %+v", recs)
			}
		})
	}
}

// Fix 18: over SSH the directory overrides of the environment are ignored
// unless a root-owned act.conf allows them.
func TestEnvOverridesOverSSH(t *testing.T) {
	argv := []string{"requeue-job", "--job-id", "7", "--mode", "hard"}
	type rig struct {
		h                  *host
		legit, evil        string // markers
		legitState, evilSt string
	}
	setup := func(t *testing.T) *rig {
		// The host's real installation is "defaults"; the environment
		// points at another catalogue, state and env directory.
		h := newHost(t)
		r := &rig{h: h, legit: filepath.Join(h.root, "ran-legit"), evil: filepath.Join(h.root, "ran-evil"),
			legitState: filepath.Join(h.root, "default-state"), evilSt: h.state}
		h.install("requeue-job", manifest(5, "1h", "10s"), "#!/bin/sh\ntouch "+r.evil+"\necho \"evil $INJECTED\"\n")
		os.WriteFile(filepath.Join(h.envDir, "requeue-job.env"), []byte("INJECTED=yes\n"), 0o600)
		legitActions := filepath.Join(h.root, "default-actions", "requeue-job")
		if err := os.MkdirAll(legitActions, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(legitActions, "action.yaml"), []byte(manifest(5, "1h", "10s")), 0o644)
		os.WriteFile(filepath.Join(legitActions, "run.sh"), []byte("#!/bin/sh\ntouch "+r.legit+"\necho \"legit ${INJECTED:-none}\"\n"), 0o755)

		oldDefaults, oldConf, oldUID := defaults, confPath, confOwnerUID
		t.Cleanup(func() { defaults, confPath, confOwnerUID = oldDefaults, oldConf, oldUID })
		defaults = dirs{catalogue: filepath.Join(h.root, "default-actions"), state: r.legitState,
			envDir: filepath.Join(h.root, "default-env")}
		confPath = filepath.Join(h.root, "act.conf")
		confOwnerUID = os.Getuid() // tests do not run as root
		h.extraEnv["DUTYDESK_ACTIONS_AUDIT_LOG"] = filepath.Join(h.root, "evil-audit.log")
		return r
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	conf := func(t *testing.T, r *rig, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(confPath, mode); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("local: overrides apply", func(t *testing.T) {
		r := setup(t)
		code, out, errb := r.h.run(argv...)
		if code != 0 || out != "evil yes\n" || !exists(r.evil) || exists(r.legit) {
			t.Errorf("code %d, stdout %q, stderr %q", code, out, errb)
		}
	})
	for _, sshVar := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		t.Run(sshVar+": overrides ignored", func(t *testing.T) {
			r := setup(t)
			r.h.extraEnv[sshVar] = "10.0.0.9 51234 10.0.0.1 22"
			code, out, errb := r.h.run(argv...)
			if code != 0 || out != "legit none\n" || exists(r.evil) || !exists(r.legit) {
				t.Errorf("code %d, stdout %q, stderr %q", code, out, errb)
			}
			if !strings.Contains(errb, "ignored") {
				t.Errorf("stderr does not say the overrides were ignored: %q", errb)
			}
			// State and audit log are the host's own, not the environment's.
			if !exists(filepath.Join(r.legitState, "audit.log")) || !exists(filepath.Join(r.legitState, "requeue-job.rate")) ||
				exists(filepath.Join(r.h.root, "evil-audit.log")) || exists(filepath.Join(r.evilSt, "requeue-job.rate")) {
				t.Error("state or audit log went where the environment said")
			}
		})
	}
	t.Run("ssh: act.conf allows the overrides", func(t *testing.T) {
		r := setup(t)
		r.h.extraEnv["SSH_CONNECTION"] = "10.0.0.9 51234 10.0.0.1 22"
		conf(t, r, "# set by the administrator\n\nallow_env_overrides = true\n", 0o644)
		code, out, errb := r.h.run(argv...)
		if code != 0 || out != "evil yes\n" || !exists(r.evil) || exists(r.legit) {
			t.Errorf("code %d, stdout %q, stderr %q", code, out, errb)
		}
	})
	t.Run("ssh: act.conf says false", func(t *testing.T) {
		r := setup(t)
		r.h.extraEnv["SSH_CONNECTION"] = "10.0.0.9 51234 10.0.0.1 22"
		conf(t, r, "allow_env_overrides=false\n", 0o600)
		if code, out, _ := r.h.run(argv...); code != 0 || out != "legit none\n" || exists(r.evil) {
			t.Errorf("code %d, stdout %q", code, out)
		}
	})
	for name, breakIt := range map[string]func(t *testing.T, r *rig){
		"group-writable": func(t *testing.T, r *rig) { conf(t, r, "allow_env_overrides = true\n", 0o664) },
		"world-writable": func(t *testing.T, r *rig) { conf(t, r, "allow_env_overrides = true\n", 0o646) },
		"not owned by root": func(t *testing.T, r *rig) {
			conf(t, r, "allow_env_overrides = true\n", 0o644)
			confOwnerUID = os.Getuid() + 1
		},
		"a link": func(t *testing.T, r *rig) {
			conf(t, r, "allow_env_overrides = true\n", 0o644)
			real := confPath + ".real"
			os.Rename(confPath, real)
			symlink(t, real, confPath)
		},
		"a directory":   func(t *testing.T, r *rig) { os.Mkdir(confPath, 0o755) },
		"unknown key":   func(t *testing.T, r *rig) { conf(t, r, "allow_env_overrides = true\nallow_everything = true\n", 0o644) },
		"bad value":     func(t *testing.T, r *rig) { conf(t, r, "allow_env_overrides = yes please\n", 0o644) },
		"not key=value": func(t *testing.T, r *rig) { conf(t, r, "allow_env_overrides\n", 0o644) },
	} {
		t.Run("ssh: act.conf refused: "+name, func(t *testing.T) {
			r := setup(t)
			r.h.extraEnv["SSH_CLIENT"] = "10.0.0.9 51234 22"
			breakIt(t, r)
			code, out, errb := r.h.run(argv...)
			if code != exitInternal || out != "" || exists(r.evil) || exists(r.legit) || !strings.Contains(errb, "act.conf") {
				t.Errorf("code %d, stdout %q, stderr %q; want exit 70 and nothing run", code, out, errb)
			}
		})
	}
	t.Run("ssh without override: act.conf is not even read", func(t *testing.T) {
		r := setup(t)
		for k := range r.h.extraEnv {
			delete(r.h.extraEnv, k)
		}
		r.h.extraEnv["SSH_CONNECTION"] = "10.0.0.9 51234 10.0.0.1 22"
		r.h.actions, r.h.state, r.h.envDir = "", "", "" // no DUTYDESK_* in the environment
		os.Mkdir(confPath, 0o755)                       // would be refused if it were read
		code, out, errb := r.h.run(argv...)
		if code != 0 || out != "legit none\n" || strings.Contains(errb, "ignored") {
			t.Errorf("code %d, stdout %q, stderr %q", code, out, errb)
		}
	})
}

// Fix 18: the CI template never installs a link.
func TestCITemplateRefusesLinks(t *testing.T) {
	data, err := os.ReadFile("../../contrib/ci/config-repo.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var code []string // the template without its comments
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	ci := strings.Join(code, "\n")
	for _, bad := range []string{"cp -r", "cp -a", "cp -R", "cp -d", "rsync -a", "-rlpt", "--links", "--copy-links", "--archive", " -l "} {
		if strings.Contains(ci, bad) {
			t.Errorf("the CI template uses %q, which keeps or follows symbolic links", bad)
		}
	}
	for _, want := range []string{"-type l", "--no-links", "install -m 0755", "install -m 0644", "! -type f"} {
		if !strings.Contains(ci, want) {
			t.Errorf("the CI template lacks %q", want)
		}
	}
}
