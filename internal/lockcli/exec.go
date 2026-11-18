// Package lockcli is how DutyDesk's core talks to the Lock Family without
// ever holding a credential: it runs the locks' clients (Reader) and reads
// lox live's read-only status socket (Status).
package lockcli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Cmd is one client invocation.
type Cmd struct {
	Argv  []string // Argv[0] is the program
	Dir   string   // working directory: the lock workspace (holds .lockfamily/)
	Env   []string // extra KEY=VALUE entries, added to the process environment
	Stdin []byte   // Run only
}

// Result is what a finished command printed.
type Result struct {
	Stdout   []byte
	ExitCode int
}

// Process is a started client that speaks on its standard streams (MCP).
type Process interface {
	Stdin() io.WriteCloser
	Stdout() io.Reader
	// Close kills the process if it still runs and releases it. It is safe
	// to call more than once and from another goroutine.
	Close() error
}

// Exec runs the lock clients. The real one is OSExec; tests use fakes.
type Exec interface {
	// Run runs the command to completion. A non-zero exit is not an error:
	// it is reported in Result.ExitCode. An error means the command could
	// not be run or was cut by ctx.
	Run(ctx context.Context, c Cmd) (Result, error)
	// Start starts the command with piped standard streams.
	Start(ctx context.Context, c Cmd) (Process, error)
}

// maxStdout bounds what Run keeps of a client's output.
const maxStdout = 16 << 20

// OSExec runs real processes. Standard error is discarded: the locks write
// human text there and DutyDesk never logs it.
type OSExec struct{}

func command(ctx context.Context, c Cmd) (*exec.Cmd, error) {
	if len(c.Argv) == 0 {
		return nil, errors.New("lockcli: empty command")
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	return cmd, nil
}

// Run implements Exec.
func (OSExec) Run(ctx context.Context, c Cmd) (Result, error) {
	cmd, err := command(ctx, c)
	if err != nil {
		return Result{}, err
	}
	out := &capWriter{max: maxStdout}
	cmd.Stdin = bytes.NewReader(c.Stdin)
	cmd.Stdout = out
	err = cmd.Run()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if out.over {
		return Result{}, errors.New("lockcli: client output too large")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{Stdout: out.buf.Bytes(), ExitCode: ee.ExitCode()}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Stdout: out.buf.Bytes()}, nil
}

// Start implements Exec.
func (OSExec) Start(ctx context.Context, c Cmd) (Process, error) {
	cmd, err := command(ctx, c)
	if err != nil {
		return nil, err
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &osProcess{cmd: cmd, in: in, out: out}, nil
}

type osProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.Reader
	once sync.Once
}

func (p *osProcess) Stdin() io.WriteCloser { return p.in }
func (p *osProcess) Stdout() io.Reader     { return p.out }

func (p *osProcess) Close() error {
	p.once.Do(func() {
		_ = p.in.Close()
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	})
	return nil
}

// capWriter keeps at most max bytes and remembers an overflow.
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(b []byte) (int, error) {
	if w.buf.Len()+len(b) > w.max {
		w.over = true
		return len(b), nil
	}
	return w.buf.Write(b)
}
