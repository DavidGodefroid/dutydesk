package lockcli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// loxLive serves the status protocol on a unix socket and returns its path.
func loxLive(t *testing.T) (string, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serving":false,"locks":{"sql-prod":"serving","ssh-restart":"needs_enrolment"},"pending":2,"detail":"ssh-restart waits for enrolment"}`))
	})
	states := map[string]string{"T1": "pending", "T2": "approved", "T3": "denied", "T4": "expired", "T5": "withdrawn", "T6": "consumed", "T7": "weird"}
	mux.HandleFunc("GET /v1/tickets/{instance}/{id}", func(w http.ResponseWriter, r *http.Request) {
		st, ok := states[r.PathValue("id")]
		if !ok || r.PathValue("instance") != "ssh-restart" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"state":"` + st + `"}`))
	})
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/withdraw", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.PathValue("instance")+"/"+r.PathValue("id"))
		mu.Unlock()
		switch r.PathValue("id") {
		case "T1":
			w.WriteHeader(http.StatusNoContent)
		case "HUMAN":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	sock := filepath.Join(t.TempDir(), "status.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock, &seen
}

func TestStatusHealth(t *testing.T) {
	sock, _ := loxLive(t)
	h, err := NewStatus(sock).Health(context.Background(), "/srv/locks/shop")
	if err != nil {
		t.Fatal(err)
	}
	want := model.LockHealth{Serving: false, Locks: map[string]string{"sql-prod": "serving", "ssh-restart": "needs_enrolment"}, Pending: 2, Detail: "ssh-restart waits for enrolment"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("health: %+v", h)
	}
}

func TestStatusTicket(t *testing.T) {
	sock, _ := loxLive(t)
	s := NewStatus(sock)
	for id, want := range map[string]model.TicketState{
		"T1": model.TicketPending, "T2": model.TicketApproved, "T3": model.TicketDenied,
		"T4": model.TicketExpired, "T5": model.TicketWithdrawn, "T6": model.TicketConsumed, "NOPE": model.TicketUnknown,
	} {
		got, err := s.Ticket(context.Background(), "ws", "ssh-restart/"+id)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v (want %q)", id, got, err, want)
		}
	}
	if st, err := s.Ticket(context.Background(), "ws", "ssh-restart/T7"); err == nil || st != model.TicketUnknown {
		t.Errorf("unknown state string: %q, %v", st, err)
	}
	for _, bad := range []string{"", "T1", "/T1", "ssh-restart/", "a/b/c", "../T1"} {
		if _, err := s.Ticket(context.Background(), "ws", bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestStatusWithdraw(t *testing.T) {
	sock, seen := loxLive(t)
	s := NewStatus(sock)
	if err := s.Withdraw(context.Background(), "ws", "ssh-restart/T1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Withdraw(context.Background(), "ws", "ssh-restart/HUMAN"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("err = %v", err)
	}
	if err := s.Withdraw(context.Background(), "ws", "ssh-restart/NOPE"); !errors.Is(err, ErrUnknownTicket) {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(*seen, []string{"ssh-restart/T1", "ssh-restart/HUMAN", "ssh-restart/NOPE"}) {
		t.Fatalf("seen: %v", *seen)
	}
}

func TestStatusSocketDown(t *testing.T) {
	s := NewStatus(filepath.Join(t.TempDir(), "absent.sock"))
	if _, err := s.Health(context.Background(), "ws"); err == nil {
		t.Fatal("want an error")
	}
	if st, err := s.Ticket(context.Background(), "ws", "a/b"); err == nil || st != model.TicketUnknown {
		t.Fatalf("%q %v", st, err)
	}
}

func TestStatusPerWorkspace(t *testing.T) {
	sock, _ := loxLive(t)
	s := NewStatusFunc(func(ws string) (string, error) {
		if ws == "/srv/locks/shop" {
			return sock, nil
		}
		return "", errors.New("unknown workspace")
	})
	if _, err := s.Health(context.Background(), "/srv/locks/shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Health(context.Background(), "/elsewhere"); err == nil {
		t.Fatal("want an error")
	}
}
