package lockcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// locklog has no query command line: its client only serves MCP on stdio
// (`locklog mcp`, locklog docs/usage.md "The agent's tools"). LogCount
// starts it, calls one tool and stops it.

const (
	toolCount       = "locklog_count" // locklog v0.4.1 internal/mcptools ToolCount
	mcpProtocol     = "2025-06-18"
	maxMCPLine      = 8 << 20
	maxContinuation = 20
)

// countResult is the console's answer to a count (locklog v0.4.1
// internal/engine CountResult): the fields read here.
type countResult struct {
	Groups []struct {
		N int64 `json:"n"`
	} `json:"groups"`
	Complete    bool   `json:"complete"`
	Cursor      string `json:"cursor"`
	GroupsTotal int    `json:"groups_total"`
	Truncated   bool   `json:"truncated"`
}

// logArgs builds the locklog_count arguments (RangeIn of locklog's
// mcptools) for a check's query over the last window.
//
// The query is either plain text, which the masked message must contain
// ("text"), or a JSON object holding the range predicates of the tool:
// "profile", "sources", "where", "text", "regex". Anything else (a time
// range, a grouping, a cursor) is refused: the window is the check's and
// the count is one number.
//
// VERIFY: model.Check.LogQuery is a string and locklog has no query
// language; this mapping is DutyDesk's own convention.
func logArgs(query string, window time.Duration) (map[string]any, error) {
	if window < time.Second {
		return nil, errors.New("lockcli: the log window must be at least one second")
	}
	args := map[string]any{}
	q := strings.TrimSpace(query)
	switch {
	case q == "":
		return nil, errors.New("lockcli: empty log query")
	case strings.HasPrefix(q, "{"):
		dec := json.NewDecoder(strings.NewReader(q))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return nil, fmt.Errorf("lockcli: the log query is not a JSON object: %w", err)
		}
		for k := range args {
			switch k {
			case "profile", "sources", "where", "text", "regex":
			default:
				return nil, fmt.Errorf("lockcli: the log query may not set %q (allowed: profile, sources, where, text, regex)", k)
			}
		}
	default:
		args["text"] = q
	}
	// "last": "the last duration, e.g. 1h or 168h (units: s, m, h)".
	args["last"] = fmt.Sprintf("%ds", int64(window/time.Second))
	return args, nil
}

// LogCount counts the records matching query over the last window, through
// the project's locklog instance.
func (r *Reader) LogCount(ctx context.Context, p *model.Project, query string, window time.Duration) (int, error) {
	if p == nil || p.Locks.Log == "" {
		return 0, ErrNoInstance
	}
	if !validName(p.Locks.Log) {
		return 0, errors.New("lockcli: invalid locklog instance name")
	}
	args, err := logArgs(query, window)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// VERIFY: locklog's host launcher sets LOCKLOG_HOST_AGENT=1 and its MCP
	// server then refuses production profiles (E_PRODUCTION_HOST_AGENT,
	// locklog docs/setup.md "The own-container recipe"). On production the
	// LogMCP template must run the client another way (the client binary in
	// DutyDesk's own container, socket volume mounted), or lox live must
	// offer a path of its own.
	proc, err := r.cfg.Exec.Start(ctx, Cmd{Argv: expand(r.cfg.LogMCP, "{instance}", p.Locks.Log), Dir: p.Locks.Workspace, Env: r.env()})
	if err != nil {
		return 0, fmt.Errorf("lockcli: locklog mcp: %w", err)
	}
	defer proc.Close()
	// A blocked read or write ends when the process is killed.
	stop := context.AfterFunc(ctx, func() { _ = proc.Close() })
	defer stop()

	n, err := countOver(newMCPConn(proc), args)
	if err != nil && ctx.Err() != nil {
		return 0, fmt.Errorf("lockcli: %s: %w", toolCount, ctx.Err())
	}
	return n, err
}

// countOver runs the MCP handshake, then the count, following the cursor of
// an incomplete answer.
func countOver(c *mcpConn, args map[string]any) (int, error) {
	if _, err := c.call("initialize", map[string]any{
		"protocolVersion": mcpProtocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "dutydesk", "version": "0"},
	}); err != nil {
		return 0, err
	}
	if err := c.notify("notifications/initialized"); err != nil {
		return 0, err
	}
	for i := 0; i <= maxContinuation; i++ {
		raw, err := c.call("tools/call", map[string]any{"name": toolCount, "arguments": args})
		if err != nil {
			return 0, err
		}
		res, err := parseCount(raw)
		if err != nil {
			return 0, err
		}
		if res.Complete {
			// Without bucket or by there is one group for the range, so
			// the answer is never paged; a paged one cannot be summed here.
			if res.Truncated || res.GroupsTotal > len(res.Groups) {
				return 0, errors.New("lockcli: locklog_count answered a paged count")
			}
			var n int64
			for _, g := range res.Groups {
				n += g.N
			}
			return int(n), nil
		}
		if res.Cursor == "" {
			return 0, ErrIncomplete
		}
		// "A result with complete: false has a cursor: passing it back with
		// the same parameters continues the same plan for free."
		// VERIFY: assumed that the last, complete answer holds the whole
		// count (the engine accumulates across continuations), so only it
		// is summed. A count over the free budgets needs locklog_scan (a
		// ticket), which a check never asks: then ErrIncomplete or the
		// lock's refusal comes back.
		args["cursor"] = res.Cursor
	}
	return 0, ErrIncomplete
}

// toolResult is an MCP tools/call result.
type toolResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	// locklog answers {"data": <console answer>} or {"refusal": {...}}
	// (mcptools Out).
	Structured *struct {
		Data    json.RawMessage `json:"data"`
		Refusal *struct {
			Code string `json:"code"`
		} `json:"refusal"`
	} `json:"structuredContent"`
}

func parseCount(raw json.RawMessage) (countResult, error) {
	var tr toolResult
	if err := json.Unmarshal(raw, &tr); err != nil {
		return countResult{}, fmt.Errorf("lockcli: %s: unreadable answer: %w", toolCount, err)
	}
	if tr.IsError || (tr.Structured != nil && tr.Structured.Refusal != nil) {
		// The tool's own text ("refused [CODE]: ...") never echoes values.
		ce := &ClientError{Tool: toolCount, Kind: "refused"}
		if tr.Structured != nil && tr.Structured.Refusal != nil {
			ce.Code = tr.Structured.Refusal.Code
		}
		if len(tr.Content) > 0 {
			ce.Message = firstLine(tr.Content[0].Text)
		}
		if strings.Contains(ce.Message, "lox run") && ce.Code == "" {
			// VERIFY: without a console the tool error asks for `lox run`
			// (mcpkit.NoConsoleLine); the exact text was not checked.
			return countResult{}, fmt.Errorf("%w: %w", ErrNoConsole, ce)
		}
		return countResult{}, ce
	}
	var data json.RawMessage
	if tr.Structured != nil {
		data = tr.Structured.Data
	}
	if len(data) == 0 {
		// Older clients: the text is one framing line, then the JSON.
		for _, c := range tr.Content {
			if i := strings.Index(c.Text, "{"); c.Type == "text" && i >= 0 {
				data = json.RawMessage(c.Text[i:])
				break
			}
		}
	}
	if len(data) == 0 {
		return countResult{}, fmt.Errorf("lockcli: %s: no data in the answer", toolCount)
	}
	var res countResult
	if err := json.Unmarshal(data, &res); err != nil {
		return countResult{}, fmt.Errorf("lockcli: %s: unreadable count: %w", toolCount, err)
	}
	return res, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ---------- minimal MCP client (JSON-RPC 2.0, one message per line) ----------

type mcpConn struct {
	w  io.Writer
	r  *bufio.Reader
	id int
}

func newMCPConn(p Process) *mcpConn {
	return &mcpConn{w: p.Stdin(), r: bufio.NewReaderSize(p.Stdout(), 64<<10)}
}

func (c *mcpConn) send(msg map[string]any) error {
	msg["jsonrpc"] = "2.0"
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("lockcli: mcp write: %w", err)
	}
	return nil
}

func (c *mcpConn) notify(method string) error {
	return c.send(map[string]any{"method": method})
}

// call sends a request and reads until its response, skipping the server's
// notifications and requests.
func (c *mcpConn) call(method string, params any) (json.RawMessage, error) {
	c.id++
	id := c.id
	if err := c.send(map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, fmt.Errorf("lockcli: mcp %s: %w", method, err)
		}
		var msg struct {
			ID     *json.Number    `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(line, &msg) != nil {
			continue // not a JSON-RPC message: ignore the line
		}
		if msg.Method != "" || msg.ID == nil || msg.ID.String() != fmt.Sprint(id) {
			continue
		}
		if msg.Error != nil {
			return nil, &ClientError{Tool: "mcp " + method, Kind: "jsonrpc", Code: fmt.Sprint(msg.Error.Code), Message: firstLine(msg.Error.Message)}
		}
		return msg.Result, nil
	}
}

func (c *mcpConn) readLine() ([]byte, error) {
	var line []byte
	for {
		part, err := c.r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > maxMCPLine {
			return nil, errors.New("message too large")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF {
				return nil, errors.New("the client closed the connection")
			}
			return nil, err
		}
		return line, nil
	}
}
