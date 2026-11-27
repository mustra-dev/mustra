package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// A whole replacement against a real database: the endpoints are found by
// serial and hostname (an ambiguous serial is refused), the one package the
// new endpoint lacks is deployed through the ordinary catalog deployment to
// the new endpoint and no other — a third endpoint that also lacks it is
// untouched — and when that endpoint reports success the job finishes and
// its report lands on the ticket in a stand-in ServiceNow.
func TestDeviceReplacementEndToEnd(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())
	s.routes()

	tag := strings.TrimPrefix(idgen.New("t"), "t")[:10]
	oldID, newID, otherID := "agt-drp-old-"+tag, "agt-drp-new-"+tag, "agt-drp-other-"+tag
	newHost := "drp-new-" + tag
	for _, a := range []struct{ id, host, serial string }{
		{oldID, "drp-old-" + tag, "SN-OLD-" + tag}, {newID, newHost, "SN-DUP-" + tag}, {otherID, "drp-other-" + tag, "SN-DUP-" + tag},
	} {
		if err := st.UpsertOnRegister(ctx, a.id, proto.AgentInfo{Hostname: a.host, OS: "linux", Arch: "amd64"}); err != nil {
			t.Fatal(err)
		}
		hw, _ := json.Marshal([]proto.HardwareInfo{{Serial: a.serial}})
		if err := st.UpsertSensorData(ctx, a.id, string(proto.SensorHardware), time.Now(), hw); err != nil {
			t.Fatal(err)
		}
		apps := []proto.InstalledApp{{Name: "bash", Version: "5.2"}}
		if a.id == oldID {
			apps = append(apps, proto.InstalledApp{Name: "drpjq" + tag, Version: "1.7.1"}, proto.InstalledApp{Name: "drpnomatch" + tag, Version: "2"})
		}
		raw, _ := json.Marshal(apps)
		if err := st.UpsertSensorData(ctx, a.id, string(proto.SensorInstalledApps), time.Now(), raw); err != nil {
			t.Fatal(err)
		}
	}

	pkgID := "sw-drp-" + tag
	t.Cleanup(func() { _ = st.DeleteSoftwarePackage(context.Background(), pkgID) })
	if _, err := st.UpsertSoftwarePackage(ctx, store.SoftwarePackage{ID: pkgID, Kind: store.KindSoftware, Name: "drpjq " + tag,
		Enabled: true, Commands: map[string]store.SoftwareOps{}, Source: "manual", CreatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	rev, err := st.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-drp-"), PackageID: pkgID, Label: "1", CreatedBy: "test",
		Definition: proto.DeployDefinition{Version: 1, Variants: []proto.DeployVariant{{
			ID: "linux", OS: "linux", Version: "1.7.1",
			Detection: &proto.DeployCheck{Kind: "app", Name: "drpjq" + tag},
			Actions: map[string]proto.DeployAction{"install": {Steps: []proto.DeployStep{{ID: "s1", Name: "install",
				Script: &proto.DeployScript{Language: "shell", Source: "apt-get install -y jq", TimeoutSeconds: 60}}}}},
		}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PublishDeployRevision(ctx, *rev); err != nil {
		t.Fatal(err)
	}

	// The stand-in ServiceNow.
	var mu sync.Mutex
	var notes []string
	snow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "svc" || p != "pw" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"result":[{"sys_id":"0123456789abcdef0123456789abcdef"}]}`)
		case http.MethodPatch:
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			notes = append(notes, r.URL.Path+"\n"+b["work_notes"])
			mu.Unlock()
			_, _ = io.WriteString(w, `{"result":{}}`)
		}
	}))
	defer snow.Close()
	intID := "int-drp-" + tag
	sealed, _ := s.sealSetting("integration/"+intID, "svc:pw")
	if err := st.SaveIntegration(ctx, store.Integration{ID: intID, Kind: "servicenow", Name: "  drp test " + tag, Enabled: true,
		Config: map[string]string{"url": snow.URL}, Events: []string{"alert"}, MinSeverity: "critical", CreatedBy: "test"}, &sealed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteIntegration(context.Background(), intID) })

	admin, err := st.CreateLocalUser(ctx, idgen.New("usr-"), "drp-admin-"+tag, "", "drp test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteUser(context.Background(), admin.ID) })
	admin.IsAdmin = true
	serve := func(pattern, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		return serveGated(s, pattern, method, path, body, admin, nil)
	}

	// Two endpoints share a serial: refused, by the gate and by the preview.
	ambiguous := `{"old_serial":"SN-DUP-` + tag + `","new_agent_id":"` + newID + `"}`
	for _, p := range []string{"POST /api/device-replacements", "POST /api/device-replacements/preview"} {
		path := strings.TrimPrefix(p, "POST ")
		if rec := serve(p, "POST", path, ambiguous); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "agent ID") {
			t.Errorf("%s with an ambiguous serial: %d %s", p, rec.Code, rec.Body)
		}
	}

	body := `{"old_serial":"sn-old-` + tag + `","new_hostname":"` + strings.ToUpper(newHost) + `","ticket":"inc0012345"}`
	rec := serve("POST /api/device-replacements/preview", "POST", "/api/device-replacements/preview", body)
	if rec.Code != 200 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	var preview deviceReplacementPreviewResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &preview)
	if len(preview.WillInstall) != 1 || preview.WillInstall[0].PackageID != pkgID || len(preview.NoMatch) != 1 || len(preview.AlreadyPresent) != 1 {
		t.Fatalf("preview: %+v", preview)
	}

	rec = serve("POST /api/device-replacements", "POST", "/api/device-replacements", body)
	if rec.Code != 200 {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	var job deviceReplacementView
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.NewAgentID != newID || job.OldAgentID != oldID || job.Ticket != "INC0012345" || len(job.Items) != 1 || job.Items[0].RunID == "" {
		t.Fatalf("job: %+v", job)
	}
	runID := job.Items[0].RunID

	// Exactly the new endpoint, although the third one lacks the package too.
	jobs, err := st.ListDeployJobs(ctx, false, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Job.AgentID != newID {
		t.Fatalf("deploy jobs of the run: %+v", jobs)
	}
	actions, err := st.ActionsForRun(ctx, runID)
	if err != nil || len(actions) != 1 || actions[0].AgentID != newID || actions[0].RequestedBy != admin.Username {
		t.Fatalf("actions of the run: %+v, %v", actions, err)
	}

	// Still running: nothing has reported, and nothing is posted.
	s.finishReplacementIfDone(ctx, job.DeviceReplacement, false)
	if got, _ := st.GetDeviceReplacement(ctx, job.ID); got == nil || got.FinishedAt != nil {
		t.Fatalf("finished before the endpoint reported: %+v", got)
	}

	if err := st.FinishAgentAction(ctx, newID, actions[0].ID, "succeeded", "installed"); err != nil {
		t.Fatal(err)
	}
	stored, _ := st.GetDeviceReplacement(ctx, job.ID)
	s.finishReplacementIfDone(ctx, *stored, false)
	s.finishReplacementIfDone(ctx, *stored, false) // a second sweep must not post twice

	done, err := st.GetDeviceReplacement(ctx, job.ID)
	if err != nil || done == nil || done.FinishedAt == nil {
		t.Fatalf("not finished: %+v %v", done, err)
	}
	if done.Items[0].Status != replInstalled || done.NoteStatus != "posted" {
		t.Errorf("finished job: items %+v, note %s %s", done.Items, done.NoteStatus, done.NoteDetail)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "/api/now/table/incident/0123456789abcdef0123456789abcdef\n") ||
		!strings.Contains(notes[0], "Installed (1):") || !strings.Contains(notes[0], "drpnomatch"+tag) {
		t.Errorf("work notes: %q", notes)
	}

	rec = serveGated(s, "GET /api/device-replacements/{id}", "GET", "/api/device-replacements/"+job.ID, "", admin, map[string]string{"id": job.ID})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"completed"`) || !strings.Contains(rec.Body.String(), `"note_status":"posted"`) {
		t.Errorf("get: %d %s", rec.Code, safeTruncate(rec.Body.String(), 400))
	}
	rec = serve("GET /api/device-replacements", "GET", "/api/device-replacements", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), job.ID) || !strings.Contains(rec.Body.String(), `"status":"completed"`) {
		t.Errorf("list: %d %s", rec.Code, safeTruncate(rec.Body.String(), 400))
	}
}
