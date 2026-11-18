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
	"math"
	"net/http"
	"os"
	"strconv"
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
	// Sentry: when the delivery was sent, in Unix seconds.
	HeaderSentryTimestamp = "Sentry-Hook-Timestamp"
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

	// RateBurst and RatePerSecond set the token bucket of each webhook
	// (project + source): RateBurst deliveries at once, then
	// RatePerSecond. Zero values give DefaultRateBurst (60) and
	// DefaultRatePerSecond (1); a negative RateBurst turns the limit off.
	RateBurst     int
	RatePerSecond float64
	// ReplaySize is how many accepted signatures are remembered, each for
	// ReplayTTL, to answer a replayed delivery without a second signal.
	// Zero values give DefaultReplaySize (4096) and DefaultReplayTTL
	// (10 minutes); a negative ReplaySize turns the cache off.
	ReplaySize int
	ReplayTTL  time.Duration
}

// Handler serves POST /hooks/{project}/{source}.
//
//	202  accepted (also a delivery that gives no signal, and a delivery
//	     that was accepted before: see replays below)
//	400  signed, but not a payload the adapter reads; or a Sentry
//	     delivery whose Sentry-Hook-Timestamp is unreadable or more than
//	     MaxTimestampSkew away from now
//	401  missing or wrong signature
//	404  unknown project or source
//	413  body over MaxBody
//	429  the webhook is over its rate (Retry-After says when to come back)
//	500  the webhook's secret or configuration cannot be used
//
// Rate: each configured webhook has a token bucket, checked before the
// body is read and before any HMAC is computed. The bucket is per webhook,
// not per sender: the endpoint does not know who is behind a proxy.
//
// Replays: the signature of an accepted delivery is remembered for
// ReplayTTL. The same delivery sent again is answered 202 like the first
// time, so a sender that retries is not told of a failure, but it gives
// neither a signal nor a resolution again. A delivery that was refused is
// not remembered. Two deliveries with the very same body are one delivery.
type Handler struct {
	o       Options
	mux     *http.ServeMux
	limits  *limiter     // nil: no limit
	replays *replayCache // nil: no cache
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
	if o.RateBurst >= 0 {
		burst, rate := o.RateBurst, o.RatePerSecond
		if burst == 0 {
			burst = DefaultRateBurst
		}
		if !(rate > 0) || math.IsInf(rate, 0) {
			rate = DefaultRatePerSecond
		}
		h.limits = newLimiter(burst, rate)
	}
	if o.ReplaySize >= 0 {
		size, ttl := o.ReplaySize, o.ReplayTTL
		if size == 0 {
			size = DefaultReplaySize
		}
		if ttl <= 0 {
			ttl = DefaultReplayTTL
		}
		h.replays = newReplayCache(size, ttl)
	}
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
	// From here on the webhook is one the configuration holds: the state
	// kept below is bounded by the configuration, not by the caller.
	hook := hookKey{p.Slug, source}
	now := h.o.Now()

	// Before any work a caller could make expensive: reading up to
	// MaxBody, the secret file, the HMAC, the JSON.
	if h.limits != nil {
		if ok, wait := h.limits.allow(hook, now); !ok {
			log.Warn("webhook refused", "reason", "over the rate limit")
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	// Sentry signs the body only: Sentry-Hook-Timestamp is NOT covered by
	// the HMAC, so whoever replays a captured delivery can also rewrite
	// or drop this header. The check stops the plain replay of a whole
	// captured request and stale retries; the replay cache below covers
	// ReplayTTL (longer than twice the skew) whatever the header says.
	// Being unsigned, it is checked before the body is read.
	if wh.Kind == "sentry" {
		if v := r.Header.Get(HeaderSentryTimestamp); v != "" && !freshTimestamp(v, now) {
			log.Warn("webhook refused", "reason", "stale or unreadable timestamp")
			http.Error(w, "stale delivery", http.StatusBadRequest)
			return
		}
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
	mac, ok := validSignature(secret, body, sig)
	if !ok {
		log.Warn("webhook refused", "reason", "bad signature")
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	var d delivery
	switch wh.Kind {
	case "sentry":
		d, err = sentry(body, r.Header.Get("Sentry-Hook-Resource"), source)
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
	if d.signal == nil && d.resolved == "" {
		return
	}
	// Only now, the delivery being one that has an effect: a refused
	// delivery may be sent again once what refused it is fixed.
	if h.replays != nil && !h.replays.firstTime(replayKey{hook, mac}, now) {
		log.Info("webhook ignored", "reason", "duplicate delivery")
		return
	}
	if d.signal != nil {
		d.signal.Project, d.signal.Source = p.Slug, source
		d.signal.Severity = wh.Severity
		d.signal.At = now
		h.o.Sink(*d.signal)
	}
	if d.resolved != "" && h.o.Resolved != nil {
		h.o.Resolved(p.Slug, source, d.resolved)
	}
}

// validSignature compares the hex HMAC-SHA256 of body in constant time
// and returns the HMAC that was computed.
func validSignature(secret, body []byte, sigHex string) (sum [sha256.Size]byte, ok bool) {
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(got) != sha256.Size {
		return sum, false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	mac.Sum(sum[:0])
	return sum, hmac.Equal(got, sum[:])
}

// freshTimestamp reads a Sentry-Hook-Timestamp (Unix seconds; a value in
// milliseconds is read as such) and reports whether it is within
// MaxTimestampSkew of now, in the past or in the future.
func freshTimestamp(v string, now time.Time) bool {
	sec, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || math.IsNaN(sec) || math.IsInf(sec, 0) || sec <= 0 {
		return false
	}
	if sec > 1e11 { // year 5138 in seconds: milliseconds
		sec /= 1000
	}
	if sec > 1e11 {
		return false
	}
	age := now.Sub(time.Unix(0, 0).Add(time.Duration(sec * float64(time.Second))))
	return age <= MaxTimestampSkew && age >= -MaxTimestampSkew
}

// configError is a webhook whose configuration cannot give a signal.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }
