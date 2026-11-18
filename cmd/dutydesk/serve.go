package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/core"
	"github.com/DavidGodefroid/dutydesk/internal/lockcli"
	"github.com/DavidGodefroid/dutydesk/internal/notify"
)

// coreAgentToken is the lock identity secret of the core itself (agent
// label "dutydesk:core"): drawn once, kept 0600 in the data directory.
func coreAgentToken(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "core-agent.token")
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); len(tok) >= 32 {
			return tok, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("core agent token: %w", err)
	}
	return tok, nil
}

func newLauncher(d *config.Daemon) (*agent.Launcher, error) {
	return agent.NewLauncher(agent.Config{
		Runtime: d.Runtime, Image: d.AgentImage, Model: d.ClaudeModel,
		Network: d.Agent.Network, HTTPSProxy: d.Agent.HTTPSProxy, NoProxy: d.Agent.NoProxy,
		MCPConfigPath: d.Agent.MCPConfig, ExtraMounts: d.Agent.ExtraMounts, RunArgs: d.Agent.RunArgs,
		User: d.Agent.User, Memory: d.Agent.Memory, CPUs: d.Agent.CPUs, PidsLimit: d.Agent.PidsLimit,
		Tokens: core.SeatTokens(d.Seats),
	})
}

// serve runs the daemon: the core service and the inbound webhook endpoint.
// It stops cleanly on SIGINT or SIGTERM.
func (c *cli) serve() error {
	d, err := c.daemon()
	if err != nil {
		return err
	}
	// Logs are structured and never hold a secret, a token or a webhook body.
	log := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	reader, err := lockReader(d)
	if err != nil {
		return err
	}
	launcher, err := newLauncher(d)
	if err != nil {
		return err
	}
	svc, err := core.New(core.Options{
		Daemon:     d,
		Reader:     reader,
		Status:     lockcli.NewStatus(d.LoxStatusSocket),
		Launcher:   launcher,
		Notifier:   &notify.Webhook{},
		Containers: agent.ExecRunner{},
		Logger:     log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var srv *http.Server
	srvErr := make(chan error, 1)
	if d.Listen != "" {
		mux := http.NewServeMux()
		mux.Handle("/hooks/", svc.Handler())
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			if !svc.Healthy() {
				http.Error(w, "unhealthy", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprintln(w, "ok")
		})
		ln, err := net.Listen("tcp", d.Listen)
		if err != nil {
			svc.Close()
			return fmt.Errorf("listen: %w", err)
		}
		srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				srvErr <- err
				stop()
			}
		}()
		log.Info("webhook endpoint listening", "addr", ln.Addr().String())
	}
	log.Info("dutydesk starting", "version", version, "data_dir", d.DataDir, "config_repo", d.ConfigRepo, "runtime", d.Runtime)

	runErr := svc.Run(ctx)
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
	}
	select {
	case err := <-srvErr:
		return fmt.Errorf("webhook endpoint: %w", err)
	default:
	}
	if runErr == nil {
		log.Info("dutydesk stopped")
	}
	return runErr
}
