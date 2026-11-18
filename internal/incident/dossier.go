package incident

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const (
	dirMode  = 0o750
	fileMode = 0o640
)

// ErrDossier wraps every failure to write the incident dossier. The state
// change it accompanies is already committed when a Manager method returns
// it, so the caller can log it and go on.
var ErrDossier = errors.New("incident: dossier")

var incidentIDRe = regexp.MustCompile(`^INC-[0-9]{1,18}$`)

// Dossier manages <data_dir>/incidents/<id>/: the memory of an incident.
//
//	incident.json   origin signal and identity (masked fields only, no secret)
//	journal.md      append-only chronological journal, written by the core
//	runs/<n>/       one directory per agent pass (transcript and
//	                verdict.json are written there by the launcher)
//
// Only the core writes here; agents get the directory mounted read-only.
// Files are 0640 and directories 0750.
type Dossier struct {
	root string
	mu   sync.Mutex
}

// NewDossier returns the dossier store rooted at <dataDir>/incidents.
func NewDossier(dataDir string) *Dossier {
	return &Dossier{root: filepath.Join(dataDir, "incidents")}
}

// Dir returns the directory of an incident, without creating it.
func (d *Dossier) Dir(id string) (string, error) {
	if !incidentIDRe.MatchString(id) {
		return "", fmt.Errorf("%w: invalid incident id %q", ErrDossier, id)
	}
	return filepath.Join(d.root, id), nil
}

// JournalPath returns the path of journal.md for an incident.
func (d *Dossier) JournalPath(id string) (string, error) {
	dir, err := d.Dir(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "journal.md"), nil
}

func (d *Dossier) ensure(id string) (string, error) {
	dir, err := d.Dir(id)
	if err != nil {
		return "", err
	}
	for _, p := range []string{d.root, dir, filepath.Join(dir, "runs")} {
		if err := mkdirAll(p); err != nil {
			return "", fmt.Errorf("%w: %v", ErrDossier, err)
		}
	}
	return dir, nil
}

// mkdirAll creates dir (and its parents) and forces mode 0750 on dir itself
// whatever the umask.
func mkdirAll(dir string) error {
	if st, err := os.Stat(dir); err == nil && st.IsDir() && st.Mode().Perm() == dirMode {
		return nil
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// incidentFile is the content of incident.json. It deliberately leaves out
// the agent token and everything that changes during the life of the
// incident (the journal tells that story).
type incidentFile struct {
	ID          string     `json:"id"`
	Project     string     `json:"project"`
	Source      string     `json:"source"`
	Fingerprint string     `json:"fingerprint"`
	Family      string     `json:"family,omitempty"`
	Severity    int        `json:"severity"`
	Summary     string     `json:"summary"`
	Mass        bool       `json:"mass,omitempty"`
	Recurrent   bool       `json:"recurrent,omitempty"`
	Runbook     string     `json:"runbook,omitempty"`
	OpenedAt    string     `json:"opened_at"`
	Signal      signalFile `json:"signal"`
}

type signalFile struct {
	Source      string            `json:"source"`
	Fingerprint string            `json:"fingerprint"`
	Severity    int               `json:"severity"`
	Summary     string            `json:"summary"`
	Fields      map[string]string `json:"fields"`
	At          string            `json:"at"`
}

// Init creates the incident directory and writes incident.json from the
// incident and its origin signal. The signal fields are stored as received:
// they are already masked or allow-listed by the source.
func (d *Dossier) Init(inc model.Incident, sig model.Signal) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dir, err := d.ensure(inc.ID)
	if err != nil {
		return err
	}
	fields := sig.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	doc := incidentFile{
		ID: inc.ID, Project: inc.Project, Source: inc.Source, Fingerprint: inc.Fingerprint, Family: inc.Family,
		Severity: int(inc.Severity), Summary: inc.Summary, Mass: inc.Mass, Recurrent: inc.Recurrent,
		Runbook: inc.Runbook, OpenedAt: stamp(inc.OpenedAt),
		Signal: signalFile{Source: sig.Source, Fingerprint: sig.Fingerprint, Severity: int(sig.Severity),
			Summary: sig.Summary, Fields: fields, At: stamp(sig.At)},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDossier, err)
	}
	if err := writeFile(filepath.Join(dir, "incident.json"), append(b, '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrDossier, err)
	}
	return nil
}

// writeFile replaces path atomically with mode 0640.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(fileMode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Append adds one entry to journal.md:
//
//	## <UTC time> — <title>
//
//	<body>
//
// The journal is append-only; entries are never rewritten. Control
// characters are stripped from the title and the body; text that comes from
// an agent or a signal must be passed through Quote by the caller.
func (d *Dossier) Append(id string, at time.Time, title, body string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dir, err := d.ensure(id)
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## %s — %s\n\n", stamp(at), inline(title))
	if body = strings.TrimSpace(model.CleanText(body)); body != "" {
		// Only Append writes headings: a body line that looks like one
		// (whatever text it came from) is quoted, so that it can never
		// pass for an entry of its own.
		lines := strings.Split(body, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "#") {
				lines[i] = "> " + l
			}
		}
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n\n")
	}
	f, err := os.OpenFile(filepath.Join(dir, "journal.md"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDossier, err)
	}
	_, err = f.WriteString(b.String())
	if err == nil {
		err = f.Chmod(fileMode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDossier, err)
	}
	return nil
}

// Journal returns the content of journal.md ("" when nothing was written).
func (d *Dossier) Journal(id string) (string, error) {
	p, err := d.JournalPath(id)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDossier, err)
	}
	return string(b), nil
}

// RunDir creates (if needed) and returns runs/<n>/ for pass number n, where
// the launcher writes the transcript and verdict.json.
func (d *Dossier) RunDir(id string, n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("%w: invalid run number %d", ErrDossier, n)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	dir, err := d.ensure(id)
	if err != nil {
		return "", err
	}
	run := filepath.Join(dir, "runs", strconv.Itoa(n))
	if err := mkdirAll(run); err != nil {
		return "", fmt.Errorf("%w: %v", ErrDossier, err)
	}
	return run, nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
