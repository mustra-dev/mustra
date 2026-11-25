package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/nativemsg"
	"github.com/mustra-dev/mustra/internal/proto"
)

var saasTestConfig = proto.SaaSConfig{Enabled: true, Revision: "r1", ExtensionID: strings.Repeat("b", 32),
	Apps: []proto.SaaSApp{{ID: "slack", Name: "Slack", Domains: []string{"slack.com"}}}}

func saasHist(i, n int) []int {
	h := make([]int, proto.SaaSHistogramLen)
	h[i] = n
	return h
}

func saasAggregate(at time.Time) proto.SaaSAggregate {
	return proto.SaaSAggregate{App: "slack", Domain: "slack.com", Browser: "chrome",
		WindowStart: at.UTC().Truncate(5 * time.Minute), WindowSeconds: 300,
		Navigations: 3, TTFBHist: saasHist(2, 3), DCLHist: saasHist(5, 3), LoadHist: saasHist(7, 3), Requests: 9, Req5xx: 1}
}

func TestSaaSMonitorAcceptAndDrain(t *testing.T) {
	m := newSaaSMonitor()
	rep := proto.SaaSReport{ExtensionVersion: "1.0.0", Aggregates: []proto.SaaSAggregate{saasAggregate(time.Now())}}
	if _, err := m.accept(rep, time.Now()); !errors.Is(err, errSaaSOff) {
		t.Fatalf("off by default: got %v", err)
	}
	if c := m.config(); c.Enabled || len(c.Apps) != 0 {
		t.Fatalf("an agent that never heard 'on' must hand out no apps: %+v", c)
	}
	m.setConfig(saasTestConfig)
	for i := 0; i < 2; i++ {
		if n, err := m.accept(rep, time.Now()); err != nil || n != 1 {
			t.Fatalf("accept: %d, %v", n, err)
		}
	}
	out, dropped := m.drain()
	if dropped != 0 || len(out.Aggregates) != 1 || out.Aggregates[0].Navigations != 6 || out.ExtensionVersion != "1.0.0" {
		t.Fatalf("drained %+v (dropped %d)", out, dropped)
	}
	if again, _ := m.drain(); len(again.Aggregates) != 0 {
		t.Fatal("drain must empty the pending set")
	}
	// An app the library does not have is refused whole.
	bad := saasAggregate(time.Now())
	bad.App = "zoom"
	if _, err := m.accept(proto.SaaSReport{Aggregates: []proto.SaaSAggregate{bad}}, time.Now()); err == nil {
		t.Fatal("unknown app accepted")
	}
	// Switching off forgets what was pending.
	_, _ = m.accept(rep, time.Now())
	m.setConfig(proto.SaaSConfig{})
	if out, _ := m.drain(); len(out.Aggregates) != 0 {
		t.Fatal("pending aggregates survived switching off")
	}
}

func TestSaaSMonitorRateLimit(t *testing.T) {
	m := newSaaSMonitor()
	m.setConfig(saasTestConfig)
	now := time.Now()
	rep := proto.SaaSReport{Aggregates: []proto.SaaSAggregate{saasAggregate(now)}}
	for i := 0; i < saasSubmitPerMinute; i++ {
		if _, err := m.accept(rep, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.accept(rep, now); !errors.Is(err, errSaaSRateLimit) {
		t.Fatalf("want rate limit, got %v", err)
	}
	if _, err := m.accept(rep, now.Add(61*time.Second)); err != nil {
		t.Fatalf("a new minute: %v", err)
	}
}

// saasListener is the agent's loopback listener as host mode sees it: the
// real guard and the real routes.
func saasListener(t *testing.T, a *Agent) (*httptest.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	token := newSelfServiceToken()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		writeLocalJSON(w, map[string]any{"token": token})
	})
	a.saasRoutes(mux)
	srv := httptest.NewUnstartedServer(newSelfServiceGuard(addr, token, mux))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, addr
}

func TestSaaSLoopbackRoutes(t *testing.T) {
	a := &Agent{saas: newSaaSMonitor()}
	a.saas.setConfig(saasTestConfig)
	_, addr := saasListener(t, a)
	base := "http://" + addr

	// A web page's cross-origin POST carries no token: refused by the guard.
	body, _ := json.Marshal(proto.SaaSReport{Aggregates: []proto.SaaSAggregate{saasAggregate(time.Now())}})
	resp, err := http.Post(base+"/api/saas/report", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tokenless post: %d", resp.StatusCode)
	}

	c, err := newLoopbackClientFor(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.config()
	if err != nil || !cfg.Enabled || len(cfg.Apps) != 1 {
		t.Fatalf("config %+v, %v", cfg, err)
	}
	n, err := c.report(proto.SaaSReport{Aggregates: []proto.SaaSAggregate{saasAggregate(time.Now())}})
	if err != nil || n != 1 {
		t.Fatalf("report: %d, %v", n, err)
	}

	// With the token, a field outside the protocol is still refused.
	tok, _ := c.token()
	req, _ := http.NewRequest("POST", base+"/api/saas/report", strings.NewReader(`{"aggregates":[],"url":"https://slack.com/messages/secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(selfServiceTokenHeader, tok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
}

func TestLoopbackClientRefusesRemoteAddresses(t *testing.T) {
	for _, u := range []string{"http://10.0.0.5:8137", "https://127.0.0.1:8137", "http://127.0.0.1:8137/api", "ftp://localhost"} {
		if _, err := newLoopbackClientFor(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8137", "http://localhost:8137", "http://[::1]:8137"} {
		if _, err := newLoopbackClientFor(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
}

// fakeAgent stands in for the loopback listener in host tests.
type fakeAgent struct {
	cfg      proto.SaaSConfig
	reported []proto.SaaSReport
}

func (f *fakeAgent) config() (proto.SaaSConfig, error) { return f.cfg, nil }
func (f *fakeAgent) report(r proto.SaaSReport) (int, error) {
	f.reported = append(f.reported, r)
	return len(r.Aggregates), nil
}

func frames(msgs ...string) *bytes.Buffer {
	var b bytes.Buffer
	for _, m := range msgs {
		_ = nativemsg.Write(&b, []byte(m))
	}
	return &b
}

func readReplies(t *testing.T, out *bytes.Buffer) []hostReply {
	t.Helper()
	var replies []hostReply
	for {
		body, err := nativemsg.Read(out, nativemsg.MaxHostToBrowser)
		if errors.Is(err, io.EOF) {
			return replies
		}
		if err != nil {
			t.Fatal(err)
		}
		var r hostReply
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		replies = append(replies, r)
	}
}

func TestNativeHostHelloAndReport(t *testing.T) {
	agent := &fakeAgent{cfg: saasTestConfig}
	rep, _ := json.Marshal(map[string]any{"type": "report", "report": proto.SaaSReport{ExtensionVersion: "1.0.0",
		Aggregates: []proto.SaaSAggregate{saasAggregate(time.Now())}}})
	var out bytes.Buffer
	code := serveNativeHost(frames(`{"type":"hello","extension_version":"1.0.0","browser":"edge"}`, string(rep)), &out, agent)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	replies := readReplies(t, &out)
	if len(replies) != 2 || replies[0].Type != "config" || replies[0].Config == nil || len(replies[0].Config.Apps) != 1 {
		t.Fatalf("hello reply %+v", replies)
	}
	if replies[1].Type != "ack" || replies[1].Accepted != 1 || len(agent.reported) != 1 {
		t.Fatalf("report reply %+v", replies[1])
	}
}

func TestNativeHostRefusesWhatIsNotTheProtocol(t *testing.T) {
	agent := &fakeAgent{cfg: saasTestConfig}
	withURL := `{"type":"report","report":{"aggregates":[{"app":"slack","url":"https://slack.com/archives/C1?q=salary"}]}}`
	unknownApp, _ := json.Marshal(map[string]any{"type": "report", "report": proto.SaaSReport{
		Aggregates: []proto.SaaSAggregate{func() proto.SaaSAggregate { a := saasAggregate(time.Now()); a.App = "zoom"; return a }()}}})
	for name, msg := range map[string]string{
		"not json":      `{"type":`,
		"unknown type":  `{"type":"exfiltrate"}`,
		"url smuggled":  withURL,
		"extra field":   `{"type":"hello","title":"Payroll - Workday"}`,
		"no report":     `{"type":"report"}`,
		"unknown app":   string(unknownApp),
		"trailing data": `{"type":"hello"} {"type":"hello"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			serveNativeHost(frames(msg), &out, agent)
			r := readReplies(t, &out)
			if len(r) != 1 || r[0].Type != "error" {
				t.Fatalf("reply %+v", r)
			}
		})
	}
	if len(agent.reported) != 0 {
		t.Fatal("a refused message reached the agent")
	}
}

func TestNativeHostFraming(t *testing.T) {
	agent := &fakeAgent{cfg: saasTestConfig}
	// A declared length over the cap: one error, then the host exits.
	var in bytes.Buffer
	hdr := make([]byte, 4)
	binary.NativeEndian.PutUint32(hdr, hostMaxIn+1)
	in.Write(hdr)
	var out bytes.Buffer
	if code := serveNativeHost(&in, &out, agent); code != 1 {
		t.Fatalf("oversize: exit %d", code)
	}
	if r := readReplies(t, &out); len(r) != 1 || r[0].Type != "error" {
		t.Fatalf("oversize reply %+v", r)
	}
	// A truncated body.
	out.Reset()
	trunc := frames(`{"type":"hello"}`).Bytes()
	if code := serveNativeHost(bytes.NewReader(trunc[:len(trunc)-3]), &out, agent); code != 1 {
		t.Fatalf("truncated: exit %d", code)
	}
	// Stdin closed with nothing sent: a clean exit and no output.
	out.Reset()
	if code := serveNativeHost(&bytes.Buffer{}, &out, agent); code != 0 || out.Len() != 0 {
		t.Fatalf("empty stdin: exit %d, %d bytes", code, out.Len())
	}
}

func TestNativeHostWhenOff(t *testing.T) {
	agent := &fakeAgent{cfg: proto.SaaSConfig{Apps: []proto.SaaSApp{}}}
	rep, _ := json.Marshal(map[string]any{"type": "report", "report": proto.SaaSReport{Aggregates: []proto.SaaSAggregate{saasAggregate(time.Now())}}})
	var out bytes.Buffer
	serveNativeHost(frames(string(rep)), &out, agent)
	if r := readReplies(t, &out); len(r) != 1 || r[0].Type != "error" || len(agent.reported) != 0 {
		t.Fatalf("reply %+v", r)
	}
}

func TestIsNativeHostInvocation(t *testing.T) {
	if !IsNativeHostInvocation([]string{"chrome-extension://abc/", "--parent-window=0"}) {
		t.Fatal("browser invocation not recognised")
	}
	for _, args := range [][]string{nil, {"--nats-url", "x"}, {"-site=chrome-extension://"}} {
		if IsNativeHostInvocation(args) {
			t.Fatalf("%v taken for a browser", args)
		}
	}
}

func TestNativeHostManifest(t *testing.T) {
	id := strings.Repeat("c", 32)
	raw, err := nativeHostManifest("/opt/mustra-agent/mustra-agent", id)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	origins, _ := m["allowed_origins"].([]any)
	if m["name"] != nativeHostName || m["type"] != "stdio" || len(origins) != 1 || origins[0] != "chrome-extension://"+id+"/" {
		t.Fatalf("manifest %s", raw)
	}
	if _, err := nativeHostManifest("/x", "*"); err == nil {
		t.Fatal("a wildcard origin must never be written")
	}
}

func TestLoopbackURL(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1:8137": "http://127.0.0.1:8137", "0.0.0.0:9000": "http://127.0.0.1:9000", "[::1]:8137": "http://[::1]:8137"} {
		if got, err := loopbackURL(in); err != nil || got != want {
			t.Errorf("%s: %s, %v", in, got, err)
		}
	}
}
