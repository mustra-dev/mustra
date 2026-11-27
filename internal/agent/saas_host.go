package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/nativemsg"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
)

// Native messaging host mode.
//
// Chrome, Edge and Chromium start a native messaging host as the signed-in
// user, with the calling extension's origin as the first argument
// (chrome-extension://<id>/) and, on Windows, a --parent-window argument
// after it. A host cannot be given flags, so this binary recognises that
// first argument and becomes the host instead of the agent (cmd/agent).
//
// The host holds no credential and talks to nothing but the running agent's
// loopback listener, whose address the agent wrote beside the binary. It
// checks what the browser sent — framing, size, schema, and nothing beyond
// the schema — before passing it on; the agent checks again.

// hostMaxIn bounds one message from the browser. Chrome allows 64 MB; a
// report is a few kilobytes.
const hostMaxIn = saasmon.MaxReportBytes + 4<<10

// IsNativeHostInvocation reports whether the process was started by a
// browser as a native messaging host.
func IsNativeHostInvocation(args []string) bool {
	return len(args) > 0 && strings.HasPrefix(args[0], "chrome-extension://")
}

// hostRequest is what the extension sends.
type hostRequest struct {
	Type string `json:"type"` // hello | report
	// ExtensionVersion and Browser are informational on hello.
	ExtensionVersion string            `json:"extension_version,omitempty"`
	Browser          string            `json:"browser,omitempty"`
	Report           *proto.SaaSReport `json:"report,omitempty"`
}

// hostReply is what the host answers, one per request.
type hostReply struct {
	Type     string            `json:"type"` // config | ack | error
	Config   *proto.SaaSConfig `json:"config,omitempty"`
	Accepted int               `json:"accepted,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// agentClient is the host's view of the agent's loopback listener.
type agentClient interface {
	config() (proto.SaaSConfig, error)
	report(proto.SaaSReport) (int, error)
}

// RunNativeHost serves the browser until it closes stdin, and returns the
// process exit code.
func RunNativeHost(args []string, in io.Reader, out io.Writer) int {
	client, err := newLoopbackAgentClient()
	if err != nil {
		_ = nativemsg.WriteJSON(out, hostReply{Type: "error", Error: err.Error()})
		return 1
	}
	return serveNativeHost(in, out, client)
}

func serveNativeHost(in io.Reader, out io.Writer, client agentClient) int {
	for {
		body, err := nativemsg.Read(in, hostMaxIn)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			// After a bad length the stream cannot be resynchronised: say why
			// and stop. The browser starts a fresh host for the next message.
			_ = nativemsg.WriteJSON(out, hostReply{Type: "error", Error: err.Error()})
			return 1
		}
		if err := nativemsg.WriteJSON(out, handleHostMessage(body, client)); err != nil {
			return 1
		}
	}
}

func handleHostMessage(body []byte, client agentClient) hostReply {
	var req hostRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	// Nothing beyond the schema: a report carrying a URL or a page title
	// is refused, not trimmed, so a broken or altered extension is noticed.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return hostReply{Type: "error", Error: "malformed message: " + err.Error()}
	}
	if dec.More() {
		return hostReply{Type: "error", Error: "malformed message: trailing data"}
	}
	switch req.Type {
	case "hello":
		cfg, err := client.config()
		if err != nil {
			return hostReply{Type: "error", Error: err.Error()}
		}
		return hostReply{Type: "config", Config: &cfg}
	case "report":
		if req.Report == nil {
			return hostReply{Type: "error", Error: "report message without a report"}
		}
		cfg, err := client.config()
		if err != nil {
			return hostReply{Type: "error", Error: err.Error()}
		}
		if !cfg.Enabled {
			return hostReply{Type: "error", Error: "SaaS monitoring is off"}
		}
		if err := saasmon.ValidateReport(*req.Report, saasmon.NewLibrary(cfg.Apps), time.Now(), saasMaxAge); err != nil {
			return hostReply{Type: "error", Error: "invalid report: " + err.Error()}
		}
		n, err := client.report(*req.Report)
		if err != nil {
			return hostReply{Type: "error", Error: err.Error()}
		}
		return hostReply{Type: "ack", Accepted: n}
	}
	return hostReply{Type: "error", Error: fmt.Sprintf("unknown message type %q", req.Type)}
}

// loopbackAgentClient calls the agent's Self Service listener.
type loopbackAgentClient struct {
	base string
	http *http.Client
}

func newLoopbackAgentClient() (*loopbackAgentClient, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), saasHostConfigName))
	if err != nil {
		return nil, errors.New("the mustra agent has not set up SaaS monitoring on this machine")
	}
	var cfg saasHostConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, errors.New("the SaaS host configuration is unreadable")
	}
	return newLoopbackClientFor(cfg.AgentURL)
}

func newLoopbackClientFor(raw string) (*loopbackAgentClient, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("the SaaS host configuration names no agent address")
	}
	// Loopback only: the file is root-owned, but a host that would send
	// what it is handed anywhere else is not one to ship.
	switch h := u.Hostname(); h {
	case "127.0.0.1", "::1", "localhost":
	default:
		return nil, fmt.Errorf("the agent address %q is not a loopback address", h)
	}
	return &loopbackAgentClient{
		base: "http://" + u.Host,
		// No proxy, whatever the user's environment says: this never
		// leaves the machine.
		http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}, nil
}

func (c *loopbackAgentClient) config() (proto.SaaSConfig, error) {
	var cfg proto.SaaSConfig
	resp, err := c.http.Get(c.base + "/api/saas/config")
	if err != nil {
		return cfg, errors.New("the mustra agent is not running or not reachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("the mustra agent answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, nativemsg.MaxHostToBrowser)).Decode(&cfg); err != nil {
		return cfg, errors.New("malformed configuration from the agent")
	}
	if err := saasmon.ValidateConfig(cfg); err != nil {
		return proto.SaaSConfig{}, err
	}
	return cfg, nil
}

func (c *loopbackAgentClient) token() (string, error) {
	resp, err := c.http.Get(c.base + "/api/session")
	if err != nil {
		return "", errors.New("the mustra agent is not running or not reachable")
	}
	defer resp.Body.Close()
	var s struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&s); err != nil || s.Token == "" {
		return "", errors.New("the mustra agent did not issue a session")
	}
	return s.Token, nil
}

func (c *loopbackAgentClient) report(r proto.SaaSReport) (int, error) {
	tok, err := c.token()
	if err != nil {
		return 0, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/api/saas/report", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(selfServiceTokenHeader, tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, errors.New("the mustra agent is not running or not reachable")
	}
	defer resp.Body.Close()
	var out struct {
		OK       bool   `json:"ok"`
		Accepted int    `json:"accepted"`
		Error    string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode != http.StatusOK || !out.OK {
		if out.Error == "" {
			out.Error = fmt.Sprintf("the mustra agent answered %d", resp.StatusCode)
		}
		return 0, errors.New(out.Error)
	}
	return out.Accepted, nil
}
