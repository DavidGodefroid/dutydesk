// Package intake is DutyDesk's inbound webhook endpoint: it verifies the
// sender's signature, keeps an allow-list of fields and hands signals on.
// Payload bodies are never logged nor kept.
package intake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// MaxBody is the largest payload accepted.
const MaxBody = 1 << 20

// Signature headers.
const (
	// Sentry (integration platform): hex HMAC-SHA256 of the raw body with
	// the integration's client secret.
	HeaderSentry = "Sentry-Hook-Signature"
	// Generic: "sha256=<hex HMAC-SHA256 of the raw body>".
	HeaderGeneric = "X-DutyDesk-Signature"
)

// Options configure a Handler. Project and Sink are required.
type Options struct {
	// Project returns the project of a slug, or nil. It is called on every
	// request, so the caller can swap its configuration at any time.
	Project func(slug string) *model.Project
	// Sink receives each signal, before the handler returns.
	Sink func(model.Signal)
	// Resolved is told when the source says the problem is over (Sentry:
	// issue resolved). Optional.
	Resolved func(project, source, fingerprint string)
	// ReadSecret reads a webhook's secret file (default: os.ReadFile).
	// Surrounding white space is dropped.
	ReadSecret func(path string) ([]byte, error)
	Now        func() time.Time
	// Logger gets one line per refused or ignored delivery: project,
	// source and reason only.
	Logger *slog.Logger
}

// Handler serves POST /hooks/{project}/{source}.
//
//	202  accepted (also a delivery that gives no signal)
//	400  signed, but not a payload the adapter reads
//	401  missing or wrong signature
//	404  unknown project or source
//	413  body over MaxBody
//	500  the webhook's secret or configuration cannot be used
type Handler struct {
	o   Options
	mux *http.ServeMux
}

// New returns the handler.
func New(o Options) (*Handler, error) {
	if o.Project == nil || o.Sink == nil {
		return nil, errors.New("intake: Project and Sink are required")
	}
	if o.ReadSecret == nil {
		o.ReadSecret = os.ReadFile
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	h := &Handler{o: o, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /hooks/{project}/{source}", h.hook)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// errIgnored: a valid delivery that is not a signal (an action or a
// resource DutyDesk does not follow).
var errIgnored = errors.New("ignored")

// delivery is what an adapter made of a payload.
type delivery struct {
	signal   *model.Signal
	resolved string // fingerprint of a resolved problem
}

func (h *Handler) hook(w http.ResponseWriter, r *http.Request) {
	slug, source := r.PathValue("project"), r.PathValue("source")
	log := h.o.Logger.With("project", slug, "source", source)
	p := h.o.Project(slug)
	if p == nil {
		http.NotFound(w, r)
		return
	}
	wh, ok := p.Webhooks[source]
	if !ok {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			log.Warn("webhook refused", "reason", "body too large")
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}

	secret, err := h.o.ReadSecret(wh.SecretFile)
	secret = bytes.TrimSpace(secret)
	if err != nil || len(secret) == 0 {
		// Never accept an unsigned delivery because a secret is missing.
		log.Error("webhook refused", "reason", "the secret cannot be read")
		http.Error(w, "webhook not configured", http.StatusInternalServerError)
		return
	}

	var sig string
	switch wh.Kind {
	case "sentry":
		sig = r.Header.Get(HeaderSentry)
	case "generic":
		var found bool
		sig, found = strings.CutPrefix(r.Header.Get(HeaderGeneric), "sha256=")
		if !found {
			sig = ""
		}
	default:
		log.Error("webhook refused", "reason", "unknown webhook kind")
		http.Error(w, "webhook not configured", http.StatusInternalServerError)
		return
	}
	if !validSignature(secret, body, sig) {
		log.Warn("webhook refused", "reason", "bad signature")
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	var d delivery
	switch wh.Kind {
	case "sentry":
		d, err = sentry(body, r.Header.Get("Sentry-Hook-Resource"))
	case "generic":
		d, err = generic(body, source, wh)
	}
	var cfg *configError
	switch {
	case errors.Is(err, errIgnored):
		log.Info("webhook ignored", "reason", "not a followed event")
	case errors.As(err, &cfg):
		log.Error("webhook refused", "reason", cfg.Error())
		http.Error(w, "webhook not configured", http.StatusInternalServerError)
		return
	case err != nil:
		// The reason names a field or a rule, never a payload value.
		log.Warn("webhook refused", "reason", err.Error())
		http.Error(w, "unsupported payload", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	if d.signal != nil {
		d.signal.Project, d.signal.Source = p.Slug, source
		d.signal.Severity = wh.Severity
		d.signal.At = h.o.Now()
		h.o.Sink(*d.signal)
	}
	if d.resolved != "" && h.o.Resolved != nil {
		h.o.Resolved(p.Slug, source, d.resolved)
	}
}

// validSignature compares the hex HMAC-SHA256 of body in constant time.
func validSignature(secret, body []byte, sigHex string) bool {
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// configError is a webhook whose configuration cannot give a signal.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

// maxValue caps a kept value.
const maxValue = 256

// clean keeps a value printable and short: control characters become
// spaces, and the value is cut at maxValue runes.
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, c := range s {
		if n == maxValue {
			break
		}
		if c < 0x20 || c == 0x7f {
			c = ' '
		}
		b.WriteRune(c)
		n++
	}
	return strings.TrimSpace(b.String())
}
