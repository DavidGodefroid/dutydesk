package agent

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// Command is one process to run.
type Command struct {
	Name   string
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Runner runs a command to completion. It returns the exit code (-1 when the
// process was killed by a signal) and a non-nil error only when the process
// could not be started or waited for. Cancelling ctx kills the process.
type Runner interface {
	Run(ctx context.Context, c Command) (exitCode int, err error)
}

// ExecRunner runs commands with os/exec. The child inherits the environment
// of the daemon (the container runtime client needs it); the container itself
// only receives what the env-file holds.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, c Command) (int, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	// A killed client may leave children holding the pipes: do not wait for them.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if errors.Is(err, exec.ErrWaitDelay) || ctx.Err() != nil {
		return -1, nil
	}
	return -1, err
}
