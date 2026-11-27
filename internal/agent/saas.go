package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
)

// SaaS experience monitoring, the agent's half.
//
// The browser extension measures; the agent is its way to the server. The
// path is: extension → Chrome native messaging → this binary started by the
// browser as the signed-in user, in host mode (saas_host.go) → the Self
// Service loopback listener of the running agent (the routes below, behind
// the same guard as the window) → the durable outbox → the server.
//
// The agent also carries the other direction: it asks the server for the
// app library every few minutes, gives it to the extension on request, and
// registers the native messaging host with Chrome, Edge and Chromium while
// monitoring is on, and removes it when it is off. Off is the default: an
// agent that never hears "on" from a server registers nothing and accepts
// nothing.

const (
	saasConfigEvery = 5 * time.Minute
	// saasPendingMax bounds what the agent holds between flushes: apps ×
	// browsers × windows. Past it new keys are dropped and counted.
	saasPendingMax = 2000
	// saasSubmitPerMinute bounds posts to the loopback route. The extension
	// sends one every five minutes per browser profile; anything far past
	// that is not the extension.
	saasSubmitPerMinute = 60
	// saasMaxAge is how old a window the agent accepts: the extension holds
	// at most a day of unsent windows.
	saasMaxAge = 48 * time.Hour
	// saasHostConfigName is written beside the agent binary for host mode
	// to find the listener; see saas_host.go.
	saasHostConfigName = "saas-host.json"
)

// saasMonitor is the agent's SaaS state: the configuration in force and
// the aggregates waiting for the next flush.
type saasMonitor struct {
	mu         sync.Mutex
	cfg        proto.SaaSConfig
	lib        saasmon.Library
	pending    map[saasmon.AggregateKey]*proto.SaaSAggregate
	extVersion string
	dropped    int
	rateStart  time.Time
	rateCount  int
	// registered is the extension ID the native host is registered for,
	// "" when it is not (or not known to be).
	registered string
	applied    bool
}

func newSaaSMonitor() *saasMonitor {
	return &saasMonitor{pending: map[saasmon.AggregateKey]*proto.SaaSAggregate{}}
}

func (m *saasMonitor) setConfig(c proto.SaaSConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = c
	m.lib = saasmon.NewLibrary(c.Apps)
	if !c.Enabled {
		// Off means nothing is kept either: what was measured before the
		// switch is not sent after it.
		m.pending = map[saasmon.AggregateKey]*proto.SaaSAggregate{}
	}
}

// config is what the extension is told. When off, the app list is
// withheld too: an extension that knows no apps measures nothing.
func (m *saasMonitor) config() proto.SaaSConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return proto.SaaSConfig{Enabled: false, Revision: m.cfg.Revision, Apps: []proto.SaaSApp{}}
	}
	c := m.cfg
	c.Apps = append([]proto.SaaSApp(nil), m.cfg.Apps...)
	if c.WindowSeconds == 0 {
		c.WindowSeconds = proto.SaaSWindowSeconds
	}
	return c
}

var (
	errSaaSOff       = errors.New("SaaS monitoring is off")
	errSaaSRateLimit = errors.New("too many reports")
)

// accept validates a report against the library in force and merges its
// aggregates into the pending set. It returns how many were kept.
func (m *saasMonitor) accept(r proto.SaaSReport, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return 0, errSaaSOff
	}
	if now.Sub(m.rateStart) >= time.Minute {
		m.rateStart, m.rateCount = now, 0
	}
	m.rateCount++
	if m.rateCount > saasSubmitPerMinute {
		return 0, errSaaSRateLimit
	}
	if err := saasmon.ValidateReport(r, m.lib, now, saasMaxAge); err != nil {
		return 0, err
	}
	if r.ExtensionVersion != "" {
		m.extVersion = r.ExtensionVersion
	}
	kept := 0
	for _, a := range r.Aggregates {
		k := saasmon.KeyOf(a)
		if cur, ok := m.pending[k]; ok {
			saasmon.Merge(cur, a)
			kept++
			continue
		}
		if len(m.pending) >= saasPendingMax {
			m.dropped++
			continue
		}
		cp := a
		cp.WindowStart = a.WindowStart.UTC()
		m.pending[k] = &cp
		kept++
	}
	return kept, nil
}

// drain takes everything pending, as a report ready to publish.
func (m *saasMonitor) drain() (proto.SaaSReport, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := proto.SaaSReport{ExtensionVersion: m.extVersion}
	for _, a := range m.pending {
		r.Aggregates = append(r.Aggregates, *a)
	}
	dropped := m.dropped
	m.pending = map[saasmon.AggregateKey]*proto.SaaSAggregate{}
	m.dropped = 0
	return r, dropped
}

// saasRoutes adds the extension's routes to the Self Service listener. They
// sit behind its guard: a POST needs the per-launch token and a JSON body,
// so a web page cannot post measurements here.
func (a *Agent) saasRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/saas/config", func(w http.ResponseWriter, r *http.Request) {
		writeLocalJSON(w, a.saas.config())
	})
	mux.HandleFunc("POST /api/saas/report", func(w http.ResponseWriter, r *http.Request) {
		var rep proto.SaaSReport
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, saasmon.MaxReportBytes))
		// Strict: a field the protocol does not have (a URL, a title) is a
		// sender that does not respect the privacy contract, and the whole
		// report goes back.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rep); err != nil {
			writeSaaSError(w, http.StatusBadRequest, "malformed report")
			return
		}
		n, err := a.saas.accept(rep, time.Now())
		if err != nil {
			status := http.StatusUnprocessableEntity
			switch {
			case errors.Is(err, errSaaSOff):
				status = http.StatusConflict
			case errors.Is(err, errSaaSRateLimit):
				status = http.StatusTooManyRequests
			}
			writeSaaSError(w, status, err.Error())
			return
		}
		writeLocalJSON(w, map[string]any{"ok": true, "accepted": n})
	})
}

func writeSaaSError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

// saasLoop keeps the configuration current and flushes aggregates.
func (a *Agent) saasLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(25 * time.Second):
	}
	tick := time.NewTicker(saasConfigEvery)
	defer tick.Stop()
	for {
		reply := a.askServer(ctx, proto.SelfServiceRequest{Action: "saas_config"})
		switch {
		case reply.SaaS != nil:
			a.applySaaSConfig(*reply.SaaS)
		case reply.Error != "" && !isUnreachable(reply.Error):
			// An older server ("unknown action") or one that refused: off.
			a.applySaaSConfig(proto.SaaSConfig{})
		}
		a.flushSaaS(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (a *Agent) applySaaSConfig(c proto.SaaSConfig) {
	if err := saasmon.ValidateConfig(c); err != nil {
		a.logger.Warn("ignoring an invalid SaaS monitoring configuration", "error", err)
		c = proto.SaaSConfig{}
	}
	a.saas.setConfig(c)
	want := ""
	if c.Enabled && c.ExtensionID != "" && a.cfg.SelfServiceAddr != "" {
		want = c.ExtensionID
	}
	a.saas.mu.Lock()
	registered, applied := a.saas.registered, a.saas.applied
	a.saas.mu.Unlock()
	if applied && registered == want {
		return
	}
	if want == "" {
		if c.Enabled && a.cfg.SelfServiceAddr == "" {
			a.logger.Warn("SaaS monitoring is on, but the Self Service listener is disabled (--self-service-addr), so the browser extension cannot reach this agent")
		}
		if err := a.unregisterSaaSHost(); err != nil {
			a.logger.Warn("could not remove the SaaS native messaging host", "error", err)
		}
	} else {
		if err := a.registerSaaSHost(want); err != nil {
			a.logger.Warn("could not register the SaaS native messaging host", "error", err)
			want = ""
		} else {
			a.logger.Info("SaaS native messaging host registered", "extension_id", want)
		}
	}
	a.saas.mu.Lock()
	a.saas.registered, a.saas.applied = want, true
	a.saas.mu.Unlock()
}

// flushSaaS publishes what is pending on the durable outbox. Aggregates
// are measurements, not a snapshot: each batch is kept (Publish, not
// PublishLatest) and the server adds it once, by its batch ID.
func (a *Agent) flushSaaS(ctx context.Context) {
	rep, dropped := a.saas.drain()
	if dropped > 0 {
		a.logger.Warn("SaaS aggregates dropped: too many apps and windows pending", "dropped", dropped)
	}
	if len(rep.Aggregates) == 0 || a.pub == nil {
		return
	}
	rep.BatchID = newSaaSBatchID()
	for start := 0; start < len(rep.Aggregates); start += saasmon.MaxAggregates {
		part := rep
		part.Aggregates = rep.Aggregates[start:min(start+saasmon.MaxAggregates, len(rep.Aggregates))]
		if start > 0 {
			part.BatchID = newSaaSBatchID()
		}
		raw, err := json.Marshal(part)
		if err != nil {
			return
		}
		snap := proto.SensorSnapshot{AgentID: a.agentID, Sensor: proto.SensorSaaS, Timestamp: time.Now().UTC(), Data: raw}
		payload, err := json.Marshal(snap)
		if err != nil {
			return
		}
		if err := a.pub.Publish(ctx, bnats.AgentSensor(a.agentID, string(proto.SensorSaaS)), payload); err != nil {
			a.logger.Warn("publish SaaS aggregates failed", "error", err)
		}
	}
}

func newSaaSBatchID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// saasHostConfig is what host mode reads beside the binary.
type saasHostConfig struct {
	AgentURL string `json:"agent_url"`
}

// loopbackURL is the Self Service address as a URL host mode can call. A
// wildcard listen address is still reached on loopback.
func loopbackURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func (a *Agent) registerSaaSHost(extensionID string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	url, err := loopbackURL(a.cfg.SelfServiceAddr)
	if err != nil {
		return fmt.Errorf("self service address: %w", err)
	}
	cfg, _ := json.Marshal(saasHostConfig{AgentURL: url})
	if err := writeFileAtomic(filepath.Join(filepath.Dir(exe), saasHostConfigName), cfg, 0o644); err != nil {
		return err
	}
	manifest, err := nativeHostManifest(exe, extensionID)
	if err != nil {
		return err
	}
	return registerNativeHost(exe, manifest)
}

func (a *Agent) unregisterSaaSHost() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if err := os.Remove(filepath.Join(filepath.Dir(exe), saasHostConfigName)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return unregisterNativeHost(exe)
}

// nativeHostName is the host's name in every browser's registry of hosts.
const nativeHostName = "dev.mustra.saas_monitor"

// nativeHostManifest is the JSON Chrome, Edge and Chromium read to find
// the host and decide which extension may start it. Exactly one origin:
// the extension the server named.
func nativeHostManifest(exe, extensionID string) ([]byte, error) {
	if !saasmon.ValidExtensionID(extensionID) {
		return nil, fmt.Errorf("invalid extension id %q", extensionID)
	}
	return json.MarshalIndent(map[string]any{
		"name":            nativeHostName,
		"description":     "mustra SaaS experience monitoring: hands the browser extension's aggregates to the mustra agent",
		"path":            exe,
		"type":            "stdio",
		"allowed_origins": []string{"chrome-extension://" + extensionID + "/"},
	}, "", "  ")
}

// writeFileAtomic writes through a temporary file and a rename, so a
// browser starting the host never reads half a manifest.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mustra-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
