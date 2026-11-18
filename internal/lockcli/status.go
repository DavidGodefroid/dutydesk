package lockcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Errors of the status socket.
var (
	// ErrNotOwner: lox live refuses to withdraw a ticket that no
	// "dutydesk:" agent requested (403).
	ErrNotOwner = errors.New("lockcli: the ticket was not requested by a dutydesk agent")
	// ErrUnknownTicket: lox live does not know the ticket (404 on withdraw).
	ErrUnknownTicket = errors.New("lockcli: unknown ticket")
)

const maxStatusBody = 1 << 20

// Status implements model.LockStatus against lox live's read-only status
// socket: HTTP/1.1 with JSON bodies over a unix socket.
//
//	GET  /v1/health                          -> 200 health
//	GET  /v1/tickets/{instance}/{id}         -> 200 {"state": ...} | 404
//	POST /v1/tickets/{instance}/{id}/withdraw -> 204 | 403 | 404
//
// It can read and withdraw DutyDesk's own tickets; it can never decide one.
type Status struct {
	socket func(workspace string) (string, error)
	client *http.Client
}

var _ model.LockStatus = (*Status)(nil)

// NewStatus reads the status socket at socketPath, whatever the workspace.
func NewStatus(socketPath string) *Status {
	return NewStatusFunc(func(string) (string, error) { return socketPath, nil })
}

// NewStatusFunc resolves the socket path per workspace (one lox live per
// workspace).
func NewStatusFunc(socket func(workspace string) (string, error)) *Status {
	s := &Status{socket: socket}
	s.client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// The socket path travels in the request context: the URL host
			// is a placeholder.
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				path, _ := ctx.Value(socketKey{}).(string)
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s
}

type socketKey struct{}

func (s *Status) do(ctx context.Context, workspace, method, path string) (int, []byte, error) {
	sock, err := s.socket(workspace)
	if err != nil {
		return 0, nil, fmt.Errorf("lockcli: status socket: %w", err)
	}
	if sock == "" {
		return 0, nil, errors.New("lockcli: no status socket for this workspace")
	}
	ctx = context.WithValue(ctx, socketKey{}, sock)
	req, err := http.NewRequestWithContext(ctx, method, "http://lox-live"+path, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("lockcli: status socket: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody))
	if err != nil {
		return 0, nil, fmt.Errorf("lockcli: status socket: %w", err)
	}
	return resp.StatusCode, body, nil
}

// Health reads the state of the hub and of every lock of the workspace.
func (s *Status) Health(ctx context.Context, workspace string) (model.LockHealth, error) {
	code, body, err := s.do(ctx, workspace, http.MethodGet, "/v1/health")
	if err != nil {
		return model.LockHealth{}, err
	}
	if code != http.StatusOK {
		return model.LockHealth{}, fmt.Errorf("lockcli: health: unexpected status %d", code)
	}
	var h struct {
		Serving bool              `json:"serving"`
		Locks   map[string]string `json:"locks"`
		Pending int               `json:"pending"`
		Detail  string            `json:"detail"`
	}
	if err := json.Unmarshal(body, &h); err != nil {
		return model.LockHealth{}, fmt.Errorf("lockcli: health: unreadable answer: %w", err)
	}
	return model.LockHealth{Serving: h.Serving, Locks: h.Locks, Pending: h.Pending, Detail: h.Detail}, nil
}

// ticketPath splits "instance/id" and builds the URL path of the ticket.
func ticketPath(ticket string) (string, error) {
	inst, id, ok := strings.Cut(ticket, "/")
	if !ok || inst == "" || id == "" || strings.Contains(id, "/") || inst == "." || inst == ".." || id == "." || id == ".." {
		return "", fmt.Errorf("lockcli: malformed ticket %q: want instance/id", ticket)
	}
	return "/v1/tickets/" + url.PathEscape(inst) + "/" + url.PathEscape(id), nil
}

// Ticket reads the state of ticket ("instance/id"). A ticket lox live does
// not know is TicketUnknown, without error.
func (s *Status) Ticket(ctx context.Context, workspace, ticket string) (model.TicketState, error) {
	path, err := ticketPath(ticket)
	if err != nil {
		return model.TicketUnknown, err
	}
	code, body, err := s.do(ctx, workspace, http.MethodGet, path)
	if err != nil {
		return model.TicketUnknown, err
	}
	switch code {
	case http.StatusOK:
	case http.StatusNotFound:
		return model.TicketUnknown, nil
	default:
		return model.TicketUnknown, fmt.Errorf("lockcli: ticket: unexpected status %d", code)
	}
	var t struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return model.TicketUnknown, fmt.Errorf("lockcli: ticket: unreadable answer: %w", err)
	}
	switch st := model.TicketState(t.State); st {
	case model.TicketPending, model.TicketApproved, model.TicketDenied, model.TicketExpired, model.TicketWithdrawn, model.TicketConsumed:
		return st, nil
	}
	return model.TicketUnknown, fmt.Errorf("lockcli: ticket: unknown state %q", t.State)
}

// Withdraw withdraws a pending ticket that a "dutydesk:" agent requested.
func (s *Status) Withdraw(ctx context.Context, workspace, ticket string) error {
	path, err := ticketPath(ticket)
	if err != nil {
		return err
	}
	code, _, err := s.do(ctx, workspace, http.MethodPost, path+"/withdraw")
	if err != nil {
		return err
	}
	switch code {
	case http.StatusNoContent:
		return nil
	case http.StatusForbidden:
		return ErrNotOwner
	case http.StatusNotFound:
		return ErrUnknownTicket
	}
	return fmt.Errorf("lockcli: withdraw: unexpected status %d", code)
}
