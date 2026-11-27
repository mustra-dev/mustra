package saasmon

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The browser extension is plain JavaScript with no build step. These run
// its own unit tests and check that what it builds is what the Go side
// accepts, when Node is installed; nothing in the extension needs npm.

func extensionDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "extension", "saas-monitor")
}

func node(t *testing.T) string {
	t.Helper()
	n, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	return n
}

func TestExtensionUnitTests(t *testing.T) {
	n := node(t)
	out, err := exec.Command(n, "--test", filepath.Join(extensionDir(t), "test", "lib.test.js")).CombinedOutput()
	if err != nil {
		t.Fatalf("extension tests failed: %v\n%s", err, out)
	}
}

// What lib.js builds passes the Go validator unchanged, its buckets and
// window are the protocol's, and decoding it strictly (as the native host
// does) finds no field outside the protocol.
func TestExtensionReportMatchesTheProtocol(t *testing.T) {
	n := node(t)
	script := `
const L = require(process.argv[1]);
const apps = [{ id: "slack", domains: ["slack.com"] }];
const now = Date.UTC(2026, 10, 25, 12, 1, 0);
const p = {};
const m = L.matchApp("app.slack.com", apps);
L.recordNavigation(p, m, "edge", now, { ttfb: 140, dcl: 950, load: 2600 });
L.recordNavigation(p, m, "edge", now, { ttfb: 30000, dcl: -1, load: -1 });
L.recordResponse(p, m, "edge", now, "xmlhttprequest", 502);
L.recordResponse(p, m, "edge", now, "main_frame", 0);
L.recordJSErrors(p, m, "edge", now, 2);
console.log(JSON.stringify({ buckets: L.BUCKETS_MS, window: L.WINDOW_SECONDS, msg: L.buildReport(p, Object.keys(p), "1.2.3") }));
`
	out, err := exec.Command(n, "-e", script, filepath.Join(extensionDir(t), "lib.js")).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got struct {
		Buckets []int           `json:"buckets"`
		Window  int             `json:"window"`
		Msg     json.RawMessage `json:"msg"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !reflect.DeepEqual(got.Buckets, proto.SaaSBucketsMs) || got.Window != proto.SaaSWindowSeconds {
		t.Fatalf("lib.js buckets %v / window %d differ from the protocol's", got.Buckets, got.Window)
	}
	var msg struct {
		Type   string           `json:"type"`
		Report proto.SaaSReport `json:"report"`
	}
	dec := json.NewDecoder(bytes.NewReader(got.Msg))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&msg); err != nil {
		t.Fatalf("the extension's report has a field outside the protocol: %v", err)
	}
	now := time.Date(2026, 11, 25, 12, 6, 0, 0, time.UTC)
	lib := NewLibrary([]proto.SaaSApp{{ID: "slack", Domains: []string{"slack.com"}}})
	if err := ValidateReport(msg.Report, lib, now, 48*time.Hour); err != nil {
		t.Fatalf("the Go side refuses what the extension builds: %v", err)
	}
	a := msg.Report.Aggregates[0]
	if a.Navigations != 2 || a.TTFBHist[proto.SaaSHistogramLen-1] != 1 || a.Req5xx != 1 || a.NavFailed != 1 || a.JSErrors != 2 || a.Browser != "edge" {
		t.Fatalf("aggregate %+v", a)
	}
}
