package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/anomaly"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The whole path on a real database with synthetic data: three endpoints
// with three days of quiet CPU, then the same climb on two of them after
// the same install, and a third endpoint too new to judge. Detection
// opens two anomalies (not the learning one), groups them with the
// shared change, the list respects management rights and suppressions,
// acknowledging is recorded, and settling closes them.
func TestAnomalyDetectionEndToEnd(t *testing.T) {
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

	agent := func(name string) string {
		id := idgen.New("agt-anom-")
		if err := st.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: name, OS: "linux"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), id) })
		return id
	}
	a, b, young := agent("anom-a"), agent("anom-b"), agent("anom-young")

	// The install finishes now; the test's clock runs six hours ahead so
	// that "now" is after it and the climb starts after it too.
	for _, id := range []string{a, b} {
		act := store.AgentAction{ID: idgen.New("act-"), AgentID: id, Kind: "catalog_install", Summary: "Install Foo 2.0", RequestedBy: "anom-test"}
		if err := st.StartAgentAction(ctx, act); err != nil {
			t.Fatal(err)
		}
		if err := st.FinishAgentAction(ctx, id, act.ID, "succeeded", ""); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Add(6 * time.Hour).Truncate(5 * time.Minute)
	// Longer ago than detection reads, so the start comes from the whole day.
	climb := now.Add(-6 * time.Hour)
	var samples []store.AnomalySample
	add := func(id string, from, to time.Time, f func(time.Time) float64) {
		for at := from; at.Before(to); at = at.Add(5 * time.Minute) {
			samples = append(samples, store.AnomalySample{AgentID: id, Metric: "cpu", At: at, Value: f(at)})
		}
	}
	quiet := func(at time.Time) float64 { return 20 + float64(at.Minute()%15)/5 } // 20-22.8
	hot := func(time.Time) float64 { return 92 }
	add(a, now.Add(-76*time.Hour), climb, quiet)
	add(a, climb, now.Add(time.Minute), hot)
	add(b, now.Add(-76*time.Hour), climb, quiet)
	add(b, climb, now.Add(time.Minute), hot)
	add(young, now.Add(-10*time.Hour), climb, quiet)
	add(young, climb, now.Add(time.Minute), hot)
	if err := st.InsertAnomalySamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	if err := st.RollUpAnomalyHours(ctx, now.Add(-80*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecomputeAnomalyBaselines(ctx, now.Add(-anomaly.BaselineWindow), now); err != nil {
		t.Fatal(err)
	}
	bs, err := st.ListAnomalyBaselines(ctx, a)
	if err != nil || len(bs) != 1 || bs[0].Hours < anomaly.MinBaselineHours || bs[0].Median < 19 || bs[0].Median > 30 {
		t.Fatalf("baseline for a: %+v %v", bs, err)
	}
	if err := s.detectAnomalies(ctx, now); err != nil {
		t.Fatal(err)
	}

	open := func() map[string]store.Anomaly {
		rows, err := st.ListAnomalies(ctx, store.AnomalyFilter{State: "open"})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.Anomaly{}
		for _, r := range rows {
			if r.AgentID == a || r.AgentID == b || r.AgentID == young {
				out[r.AgentID] = r
			}
		}
		return out
	}
	got := open()
	if len(got) != 2 || got[young].ID != "" {
		t.Fatalf("open anomalies %+v, want a and b only (the young endpoint is learning)", got)
	}
	for _, id := range []string{a, b} {
		x := got[id]
		if x.Direction != anomaly.High || x.Change != "Install Foo 2.0" || x.PeakValue != 92 || x.Severity == "" {
			t.Fatalf("anomaly on %s: %+v", id, x)
		}
		if x.StartedAt.Before(climb) || x.StartedAt.After(climb.Add(time.Hour)) {
			t.Fatalf("started %v, want shortly after %v", x.StartedAt, climb)
		}
	}
	// A second pass on the same data changes nothing: one open per
	// endpoint and metric.
	if err := s.detectAnomalies(ctx, now); err != nil {
		t.Fatal(err)
	}
	if again := open(); again[a].ID != got[a].ID || len(again) != 2 {
		t.Fatalf("second pass: %+v", again)
	}

	// The list, as an administrator, grouped with the shared change.
	admin := &store.User{ID: "usr-anom-admin", Username: "anom-admin", IsAdmin: true}
	list := func(u *store.User, query string) listAnomaliesResponse {
		req := httptest.NewRequest("GET", "/api/anomalies"+query, nil).WithContext(auth.WithUser(ctx, u))
		w := httptest.NewRecorder()
		s.handleListAnomalies(w, req)
		if w.Code != 200 {
			t.Fatalf("list: %d %s", w.Code, w.Body)
		}
		var out listAnomaliesResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	mine := func(r listAnomaliesResponse) (g *anomalyGroupView, n int) {
		for _, x := range r.Anomalies {
			if x.AgentID == a || x.AgentID == b {
				n++
			}
		}
		for i := range r.Groups {
			if r.Groups[i].ID == "cpu-high" {
				g = &r.Groups[i]
			}
		}
		return g, n
	}
	g, n := mine(list(admin, ""))
	if n != 2 || g == nil || g.Change != "Install Foo 2.0" || g.ChangeEndpoints < 2 || g.Active < 2 {
		t.Fatalf("admin list: %d of ours, group %+v", n, g)
	}

	// Detail: the chart's samples and band come back.
	req := httptest.NewRequest("GET", "/api/anomalies/"+got[a].ID, nil).WithContext(auth.WithUser(ctx, admin))
	req.SetPathValue("id", got[a].ID)
	w := httptest.NewRecorder()
	s.handleGetAnomaly(w, req)
	var det anomalyDetailResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &det) != nil || !det.Ready || len(det.Hours) < 48 || det.Band.Hi < 30 {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String()[:min(400, w.Body.Len())])
	}

	// A user whose management rights cover only a group holding b sees b,
	// not a, and gets a 404 for a's detail.
	grp := store.ComputerGroup{ID: idgen.New("cgrp-"), Name: idgen.New("anom-only-b-"), Kind: "static", MemberIDs: []string{b}}
	if _, err := st.UpsertComputerGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = st.DeleteComputerGroupAndOrphans(context.Background(), grp.ID) })
	scoped, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("anom-scoped-"), "", "anomaly test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteUser(context.Background(), scoped.ID) })
	role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("anom-role-"), "", []string{auth.PermFleetRead, auth.PermAlertsTriage}, []string{grp.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteRole(context.Background(), role.ID) })
	if err := st.AssignUserRole(ctx, scoped.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	s.invalidateAccess()
	for _, x := range list(scoped, "").Anomalies {
		if x.AgentID == a {
			t.Fatal("a scoped user sees an endpoint outside their management rights")
		}
	}
	req = httptest.NewRequest("GET", "/api/anomalies/"+got[a].ID, nil).WithContext(auth.WithUser(ctx, scoped))
	req.SetPathValue("id", got[a].ID)
	w = httptest.NewRecorder()
	s.handleGetAnomaly(w, req)
	if w.Code != 404 {
		t.Fatalf("scoped detail of a: %d, want 404", w.Code)
	}
	// Nor may they suppress fleet-wide, or acknowledge a.
	post := func(u *store.User, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body)).WithContext(auth.WithUser(ctx, u))
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}
	if w := post(scoped, s.handleCreateAnomalySuppression, `{"metric":"cpu","reason":"x"}`); w.Code != 403 {
		t.Fatalf("scoped fleet-wide suppression: %d, want 403", w.Code)
	}
	w = post(scoped, s.handleAckAnomalies, `{"ids":["`+got[a].ID+`","`+got[b].ID+`"],"note":"seen"}`)
	var ack ackAnomaliesResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ack) != nil || len(ack.Acknowledged) != 1 || ack.Acknowledged[0] != got[b].ID {
		t.Fatalf("scoped ack: %d %s, want only b", w.Code, w.Body)
	}

	// A suppression on b's group hides b from the admin's list unless
	// asked for, and counts it.
	w = post(admin, s.handleCreateAnomalySuppression, `{"metric":"cpu","group_id":"`+grp.ID+`","reason":"expected","days":1}`)
	if w.Code != 201 {
		t.Fatalf("suppress: %d %s", w.Code, w.Body)
	}
	var sup store.AnomalySuppression
	_ = json.Unmarshal(w.Body.Bytes(), &sup)
	t.Cleanup(func() { _, _ = st.DeleteAnomalySuppression(context.Background(), sup.ID) })
	r := list(admin, "")
	for _, x := range r.Anomalies {
		if x.AgentID == b {
			t.Fatal("a suppressed anomaly is listed without suppressed=1")
		}
	}
	if r.Suppressed < 1 {
		t.Fatalf("suppressed count %d", r.Suppressed)
	}
	found := false
	for _, x := range list(admin, "?suppressed=1").Anomalies {
		if x.AgentID == b && x.Suppressed && x.SuppressionID == sup.ID && x.AcknowledgedBy == scoped.Username {
			found = true
		}
	}
	if !found {
		t.Fatal("suppressed=1 does not list b as suppressed and acknowledged")
	}

	// Settling: two hours back at normal closes both.
	samples = samples[:0]
	add(a, now.Add(5*time.Minute), now.Add(2*time.Hour+time.Minute), quiet)
	add(b, now.Add(5*time.Minute), now.Add(2*time.Hour+time.Minute), quiet)
	if err := st.InsertAnomalySamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	if err := s.detectAnomalies(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if left := open(); len(left) != 0 {
		t.Fatalf("still open after settling: %+v", left)
	}
	closed, err := st.GetAnomaly(ctx, got[a].ID)
	if err != nil || closed == nil || closed.EndedAt == nil || closed.NoData || !closed.EndedAt.After(now) {
		t.Fatalf("closed anomaly: %+v %v", closed, err)
	}
}
