package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// ErrNoWebhook means the project has no outgoing webhook configured.
var ErrNoWebhook = errors.New("notify: no webhook configured")

// Webhook sends alerts to the URL stored in Project.Alerts.WebhookURLFile.
// The payload is a Microsoft Teams message (incoming webhook or Power Automate
// workflow) holding an Adaptive Card, with a plain "text" field for generic
// receivers. The URL is a secret: it never appears in errors or logs.
type Webhook struct {
	Client   *http.Client    // default: 10 s timeout, redirects not followed
	Attempts int             // default 3
	Backoff  []time.Duration // wait before each retry, default 1 s then 3 s
}

var _ model.Notifier = (*Webhook)(nil)

var defaultClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Payload builds the JSON message for an alert.
func Payload(a model.Alert) ([]byte, error) {
	title, text := Format(a)
	facts := []map[string]string{{"title": "Kind", "value": KindLabel(a.Kind)}}
	if a.Project != "" {
		facts = append(facts, map[string]string{"title": "Project", "value": a.Project})
	}
	if a.Incident != "" {
		facts = append(facts, map[string]string{"title": "Incident", "value": a.Incident})
	}
	if !a.At.IsZero() {
		facts = append(facts, map[string]string{"title": "At", "value": a.At.UTC().Format("2006-01-02 15:04 UTC")})
	}
	body := []any{
		map[string]any{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true},
		map[string]any{"type": "FactSet", "facts": facts},
	}
	if text != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": text, "wrap": true})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if u, err := url.Parse(a.URL); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open", "url": a.URL}}
	}
	fallback := title
	if text != "" {
		fallback += "\n" + text
	}
	return json.Marshal(map[string]any{
		"type": "message",
		"text": fallback,
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	})
}

// Send posts the alert. Network errors and 5xx answers are retried with a
// backoff; a 4xx answer is final.
func (w *Webhook) Send(ctx context.Context, p *model.Project, a model.Alert) error {
	if p == nil || p.Alerts.WebhookURLFile == "" {
		return ErrNoWebhook
	}
	raw, err := os.ReadFile(p.Alerts.WebhookURLFile)
	if err != nil {
		return fmt.Errorf("notify: webhook URL file: %w", err)
	}
	target := strings.TrimSpace(string(raw))
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("notify: webhook URL file does not hold an http(s) URL")
	}
	payload, err := Payload(a)
	if err != nil {
		return err
	}
	client := w.Client
	if client == nil {
		client = defaultClient
	}
	attempts := w.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	backoff := w.Backoff
	if backoff == nil {
		backoff = []time.Duration{time.Second, 3 * time.Second}
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			wait := time.Duration(0)
			if len(backoff) > 0 {
				wait = backoff[min(i-1, len(backoff)-1)]
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("notify: webhook: %w (last error: %v)", ctx.Err(), last)
			case <-time.After(wait):
			}
		}
		retry, err := post(ctx, client, target, payload)
		if err == nil {
			return nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return last
}

// post sends one request. Its errors never contain the URL.
func post(ctx context.Context, client *http.Client, target string, payload []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return false, errors.New("notify: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dutydesk")
	resp, err := client.Do(req)
	if err != nil {
		return true, fmt.Errorf("notify: webhook request failed: %s", scrub(err, target))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return false, nil
	case resp.StatusCode >= 500:
		return true, fmt.Errorf("notify: webhook answered HTTP %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("notify: webhook answered HTTP %d", resp.StatusCode)
	}
}

// scrub renders a client error without the URL it was sent to.
func scrub(err error, target string) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := strings.ReplaceAll(err.Error(), target, "[webhook]")
	if u, perr := url.Parse(target); perr == nil {
		if p := u.RequestURI(); len(p) > 1 {
			msg = strings.ReplaceAll(msg, p, "[webhook]")
		}
	}
	return msg
}
