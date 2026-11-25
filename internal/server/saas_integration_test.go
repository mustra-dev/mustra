package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func saasFixture(t *testing.T) (*Server, *store.Store, string, string) {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	agent := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "saas-" + agent, OS: "windows", Arch: "amd64", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agent) })
	app := "it-" + idgen.New("")[:12]
	if _, err := st.CreateSaaSApp(ctx, store.SaaSApp{ID: app, Name: "Integration " + app, Domains: []string{app + ".example"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteSaaSApp(context.Background(), app) })
	prev, _ := st.GetSetting(ctx, settingSaaS)
	t.Cleanup(func() { _ = st.SetSetting(context.Background(), settingSaaS, prev, "test") })
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}, trust: &agentTrust{publicURLEnv: "https://console.example.com"}}
	s.live.setAgent(time.Hour, 0, "")
	return s, st, agent, app
}

func setSaaS(t *testing.T, st *store.Store, v saasSettings) {
	t.Helper()
	raw, _ := json.Marshal(v)
	if err := st.SetSetting(context.Background(), settingSaaS, string(raw), "test"); err != nil {
		t.Fatal(err)
	}
}

func saasSnapshot(t *testing.T, agent, batch string, aggs ...proto.SaaSAggregate) proto.SensorSnapshot {
	t.Helper()
	raw, _ := json.Marshal(proto.SaaSReport{BatchID: batch, ExtensionVersion: "1.0.0", Aggregates: aggs})
	norm, err := normalizeSnapshotData(proto.SensorSaaS, raw)
	if err != nil {
		t.Fatal(err)
	}
	return proto.SensorSnapshot{AgentID: agent, Sensor: proto.SensorSaaS, Timestamp: time.Now().UTC(), Data: norm}
}

func agg(app string, at time.Time, navs, bucket int) proto.SaaSAggregate {
	h := make([]int, proto.SaaSHistogramLen)
	h[bucket] = navs
	return proto.SaaSAggregate{App: app, Domain: app + ".example", Browser: "edge", WindowStart: at, WindowSeconds: 300, Navigations: navs,
		TTFBHist: h, DCLHist: h, LoadHist: h, Requests: navs * 4}
}

func getJSONFrom(t *testing.T, h http.HandlerFunc, target string, pathValues map[string]string, into any) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code == 200 && into != nil {
		if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
			t.Fatalf("%s: %v\n%s", target, err, w.Body.String())
		}
	}
	return w.Code
}

func TestSaaSConfigFollowsTheSwitch(t *testing.T) {
	s, st, agent, app := saasFixture(t)
	ctx := context.Background()
	setSaaS(t, st, saasSettings{})
	reply := s.handleSelfService(ctx, agent, proto.SelfServiceRequest{Action: "saas_config"})
	if reply.SaaS == nil || reply.SaaS.Enabled || len(reply.SaaS.Apps) != 0 {
		t.Fatalf("off: %+v", reply.SaaS)
	}
	off := reply.SaaS.Revision
	setSaaS(t, st, saasSettings{Enabled: true, ExtensionID: strings.Repeat("a", 32)})
	reply = s.handleSelfService(ctx, agent, proto.SelfServiceRequest{Action: "saas_config"})
	cfg := reply.SaaS
	if cfg == nil || !cfg.Enabled || cfg.ExtensionID != strings.Repeat("a", 32) || cfg.Revision == off {
		t.Fatalf("on: %+v", cfg)
	}
	found := false
	for _, a := range cfg.Apps {
		found = found || a.ID == app
	}
	if !found {
		t.Fatal("the library's app is not in the config")
	}
	if err := saasmon.ValidateConfig(*cfg); err != nil {
		t.Fatalf("what the server sends must pass the agent's own check: %v", err)
	}
}

func TestSaaSReportsAreScored(t *testing.T) {
	s, st, agent, app := saasFixture(t)
	ctx := context.Background()
	w := time.Now().UTC().Truncate(5 * time.Minute).Add(-30 * time.Minute)

	// Off: discarded.
	setSaaS(t, st, saasSettings{})
	if err := s.recordSaaSReport(ctx, saasSnapshot(t, agent, "off-"+app, agg(app, w, 50, 2))); err != nil {
		t.Fatal(err)
	}
	setSaaS(t, st, saasSettings{Enabled: true, RetentionDays: 7})
	// On: an unknown app and a window past retention are dropped; the
	// rest counts, once however often the batch is delivered.
	snap := saasSnapshot(t, agent, "on-"+app, agg(app, w, 20, 2), agg("not-in-library-"+app[3:], w, 9, 2),
		agg(app, time.Now().UTC().Truncate(5*time.Minute).AddDate(0, 0, -8), 7, 2))
	for i := 0; i < 2; i++ {
		if err := s.recordSaaSReport(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	var ov saasOverviewResponse
	if code := getJSONFrom(t, s.handleSaaSOverview, "/api/saas/overview?hours=24", nil, &ov); code != 200 {
		t.Fatalf("overview %d", code)
	}
	var mine *saasAppScore
	for i := range ov.Apps {
		if ov.Apps[i].AppID == app {
			mine = &ov.Apps[i]
		}
	}
	if mine == nil || mine.Navigations != 20 || mine.Endpoints != 1 || mine.Score == nil || *mine.Score != 100 {
		t.Fatalf("overview row %+v", mine)
	}
	var eps saasAppEndpointsResponse
	if code := getJSONFrom(t, s.handleSaaSAppEndpoints, "/api/saas/apps/"+app+"/endpoints", map[string]string{"id": app}, &eps); code != 200 {
		t.Fatalf("endpoints %d", code)
	}
	if len(eps.Endpoints) != 1 || eps.Endpoints[0].AgentID != agent || eps.Endpoints[0].Hostname != "saas-"+agent || eps.Endpoints[0].ExtensionVersion != "1.0.0" {
		t.Fatalf("endpoints %+v", eps.Endpoints)
	}
	var tr saasTrendResponse
	if code := getJSONFrom(t, s.handleSaaSAppTrend, "/api/saas/apps/"+app+"/trend?hours=24", map[string]string{"id": app}, &tr); code != 200 {
		t.Fatalf("trend %d", code)
	}
	if tr.BucketSeconds != 3600 || len(tr.Points) != 1 || tr.Points[0].Navigations != 20 {
		t.Fatalf("trend %+v", tr)
	}
	if code := getJSONFrom(t, s.handleSaaSAppTrend, "/x", map[string]string{"id": "no-such-app"}, nil); code != 404 {
		t.Fatalf("unknown app trend: %d", code)
	}
	if code := getJSONFrom(t, s.handleSaaSOverview, "/api/saas/overview?hours=0", nil, nil); code != 400 {
		t.Fatalf("hours=0: %d", code)
	}
	// The endpoint page's cache holds the summary.
	row, err := st.GetSensorData(ctx, agent, string(proto.SensorSaaS))
	if err != nil || row == nil || !strings.Contains(string(row.Data), app) {
		t.Fatalf("sensor cache %v %v", row, err)
	}
}

func testCRX(t *testing.T, key *rsa.PrivateKey, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("manifest.json")
	f.Write([]byte(`{"manifest_version":3,"name":"mustra SaaS experience monitor","version":"` + version + `"}`))
	zw.Close()
	crx, _, err := saasmon.BuildCRX(buf.Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	return crx
}

func TestSaaSExtensionUploadAndUpdateManifest(t *testing.T) {
	s, st, _, _ := saasFixture(t)
	ctx := context.Background()
	prevExt, prevData, _ := st.GetSaaSExtension(ctx, true)
	t.Cleanup(func() {
		if prevExt != nil {
			_ = st.PutSaaSExtension(context.Background(), *prevExt, prevData)
		} else {
			_ = st.DeleteSaaSExtension(context.Background())
		}
	})
	_ = st.DeleteSaaSExtension(ctx)
	upload := func(body []byte, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/saas/extension"+query, bytes.NewReader(body))
		r = r.WithContext(auth.WithUser(r.Context(), &store.User{ID: "u-saas", Username: "saas-admin", IsAdmin: true}))
		w := httptest.NewRecorder()
		s.handleUploadSaaSExtension(w, r)
		return w
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	crx := testCRX(t, key, "1.0.0")
	w := upload(crx, "")
	if w.Code != 200 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var meta store.SaaSExtension
	_ = json.Unmarshal(w.Body.Bytes(), &meta)
	if !saasmon.ValidExtensionID(meta.ExtensionID) || meta.Version != "1.0.0" {
		t.Fatalf("meta %+v", meta)
	}
	// Garbage, and a tampered package, are refused.
	if w := upload([]byte("not a crx"), ""); w.Code != 400 {
		t.Fatalf("garbage: %d", w.Code)
	}
	bad := append([]byte(nil), crx...)
	bad[len(bad)-40] ^= 1
	if w := upload(bad, ""); w.Code != 400 {
		t.Fatalf("tampered: %d", w.Code)
	}
	// Another key is another extension: refused unless asked for.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if w := upload(testCRX(t, other, "1.0.1"), ""); w.Code != 409 {
		t.Fatalf("different key: %d", w.Code)
	}
	// The update manifest names the package by ID, version and hash.
	mw := httptest.NewRecorder()
	s.handleSaaSUpdateManifest(mw, httptest.NewRequest(http.MethodGet, saasUpdatePath, nil))
	body := mw.Body.String()
	for _, want := range []string{`appid="` + meta.ExtensionID + `"`, `version="1.0.0"`, `hash_sha256="` + meta.SHA256 + `"`, "https://console.example.com" + saasCRXPath} {
		if !strings.Contains(body, want) {
			t.Fatalf("update manifest lacks %q:\n%s", want, body)
		}
	}
	cw := httptest.NewRecorder()
	s.handleSaaSCRX(cw, httptest.NewRequest(http.MethodGet, saasCRXPath, nil))
	if cw.Code != 200 || !bytes.Equal(cw.Body.Bytes(), crx) || cw.Header().Get("Content-Type") != "application/x-chrome-extension" {
		t.Fatalf("crx download: %d", cw.Code)
	}
	// The package's ID is what agents admit.
	setSaaS(t, st, saasSettings{Enabled: true, ExtensionID: strings.Repeat("b", 32)})
	if cfg := s.saasConfigFor(ctx); cfg.ExtensionID != meta.ExtensionID {
		t.Fatalf("agents admit %q, want the package's %q", cfg.ExtensionID, meta.ExtensionID)
	}
}
