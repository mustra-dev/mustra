package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func rolloutFixture(t *testing.T) (*Server, *store.Store, []string) {
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
	var ids []string
	for i := 0; i < 3; i++ {
		id := idgen.New("agt-")
		if err := st.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: "ring-" + id, OS: "linux", Arch: "amd64", Version: "0.60.0"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), id) })
		if err := st.RecordHeartbeat(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}, runs: newInflight()}
	s.live.setAgent(time.Hour, 0, "")
	return s, st, ids
}

func staticGroup(t *testing.T, st *store.Store, name string, members ...string) string {
	t.Helper()
	g, err := st.UpsertComputerGroup(context.Background(), store.ComputerGroup{
		ID: idgen.New("cgrp-"), Name: name + " " + idgen.New(""), Kind: "static", MatchMode: "all", MemberIDs: members, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = st.DeleteComputerGroupAndOrphans(context.Background(), g.ID) })
	return g.ID
}

func reportPolicy(t *testing.T, st *store.Store, groupID string) store.EnforcePolicy {
	t.Helper()
	settings, _ := json.Marshal([]proto.EnforceSetting{{ID: "set-fw", Name: "Firewall on", Rules: []string{"c:true"}, RemediateLinux: "true"}})
	p := store.EnforcePolicy{ID: idgen.New("enf-"), Name: "Ring test " + idgen.New(""), GroupID: groupID, Mode: "report",
		Enabled: true, Settings: settings, UpdatedBy: "jdoe", Config: json.RawMessage("{}")}
	if err := st.UpsertEnforcePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteEnforcePolicy(context.Background(), p.ID) })
	got, err := st.GetEnforcePolicy(context.Background(), p.ID)
	if err != nil || got == nil {
		t.Fatalf("read policy back: %v", err)
	}
	return *got
}

func promotedIDs(s *Server, p store.EnforcePolicy) []string {
	var out []string
	for id := range s.enforcePromoted(context.Background(), p) {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	sort.Strings(out)
	return out
}

// An Enforce policy promoted ring by ring enforces on the pilot first,
// moves to the next ring once the pilot's results pass, halts on a ring
// whose group was deleted (without widening), and goes back to report
// everywhere when aborted.
func TestEnforceRolloutPromotesRingByRing(t *testing.T) {
	s, st, ids := rolloutFixture(t)
	ctx := context.Background()
	all := staticGroup(t, st, "all", ids...)
	pilot := staticGroup(t, st, "pilot", ids[0])
	rest := staticGroup(t, st, "rest", ids[1], ids[2])
	p := reportPolicy(t, st, all)
	plan := store.DeploymentPlan{ID: idgen.New("plan-"), Name: "pilot then rest", Kind: "custom", Rings: []store.Ring{
		{Name: "Pilot", GroupID: pilot, SuccessRate: 100},
		{Name: "Rest", GroupID: rest},
	}}

	ro, err := s.startRollout(ctx, "enforce", p.ID, p.Name, plan, struct{}{}, "jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if ro.Rings[0].State != "running" || !slices.Equal(ro.Rings[0].AgentIDs, []string{ids[0]}) {
		t.Fatalf("pilot ring: %+v", ro.Rings[0])
	}
	if got := promotedIDs(s, p); !slices.Equal(got, []string{ids[0]}) {
		t.Fatalf("promoted %v, want only the pilot", got)
	}
	if _, err := s.startRollout(ctx, "enforce", p.ID, p.Name, plan, struct{}{}, "jdoe"); !errors.Is(err, store.ErrRolloutOpen) {
		t.Fatalf("a second open rollout of one policy: %v", err)
	}

	// The pilot passes once its pass has run and its results are in.
	s.rolloutPasses.Store(ro.ID+"#0", time.Now())
	if _, err := st.RecordEnforceResult(ctx, store.EnforceResult{AgentID: ids[0], PolicyID: p.ID, SettingID: "set-fw", Name: "Firewall on", State: "remediated"}); err != nil {
		t.Fatal(err)
	}
	// The rest ring's group goes away before it starts.
	if _, _, err := st.DeleteComputerGroupAndOrphans(ctx, rest); err != nil {
		t.Fatal(err)
	}
	s.stepRollout(ctx, ro.ID)
	ro, _ = st.GetRingRollout(ctx, ro.ID)
	if ro.Rings[0].State != "passed" || ro.Status != "halted" || ro.Rings[1].State != "pending" || len(ro.Rings[1].AgentIDs) != 0 {
		t.Fatalf("after the pilot passed with the next ring's group gone: status %s, rings %+v", ro.Status, ro.Rings)
	}
	if got := promotedIDs(s, p); !slices.Equal(got, []string{ids[0]}) {
		t.Fatalf("a halted rollout promoted %v, want still only the pilot", got)
	}
	if fresh, _ := st.GetEnforcePolicy(ctx, p.ID); fresh.Mode != "report" {
		t.Fatalf("policy mode %s before the rollout finished", fresh.Mode)
	}

	if err := abortRollout(ro, "jdoe", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.SaveRingRollout(ctx, ro); err != nil || !ok {
		t.Fatalf("save abort: %v %v", ok, err)
	}
	if got := promotedIDs(s, p); len(got) != 0 {
		t.Fatalf("an aborted rollout still promotes %v", got)
	}
}

// The last ring passing switches the policy itself to enforce.
func TestEnforceRolloutFinishSwitchesPolicy(t *testing.T) {
	s, st, ids := rolloutFixture(t)
	ctx := context.Background()
	all := staticGroup(t, st, "all", ids...)
	p := reportPolicy(t, st, all)
	plan := store.DeploymentPlan{ID: idgen.New("plan-"), Name: "everyone", Kind: "dynamic", Rings: []store.Ring{{Name: "All", Percent: 100, SuccessRate: 60}}}
	ro, err := s.startRollout(ctx, "enforce", p.ID, p.Name, plan, struct{}{}, "jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if got := sorted(ro.Rings[0].AgentIDs...); !slices.Equal(got, sorted(ids...)) {
		t.Fatalf("a 100%% ring of the policy's group took %v", got)
	}
	s.rolloutPasses.Store(ro.ID+"#0", time.Now())
	for _, id := range ids[:2] {
		if _, err := st.RecordEnforceResult(ctx, store.EnforceResult{AgentID: id, PolicyID: p.ID, SettingID: "set-fw", Name: "Firewall on", State: "compliant"}); err != nil {
			t.Fatal(err)
		}
	}
	s.stepRollout(ctx, ro.ID)
	ro, _ = st.GetRingRollout(ctx, ro.ID)
	if ro.Status != "completed" || ro.Rings[0].Outcome.Succeeded != 2 || ro.Rings[0].Outcome.NoResponse != 1 {
		t.Fatalf("2 of 3 against 60%%: status %s, outcome %+v", ro.Status, ro.Rings[0].Outcome)
	}
	if fresh, _ := st.GetEnforcePolicy(ctx, p.ID); fresh.Mode != "enforce" {
		t.Fatalf("policy mode %s after the rollout completed, want enforce", fresh.Mode)
	}
	if got := promotedIDs(s, p); len(got) != 0 {
		t.Fatalf("a finished rollout still promotes %v", got)
	}
}

// A failed patch health check in a ring's run halts the rollout it belongs
// to, and a stale read cannot overwrite a newer write.
func TestPatchHealthHoldHaltsRollout(t *testing.T) {
	s, st, ids := rolloutFixture(t)
	ctx := context.Background()
	runID := idgen.New("run-")
	now := time.Now().UTC()
	ro, err := st.CreateRingRollout(ctx, store.RingRollout{
		ID: idgen.New("rollout-"), Kind: "patch", SourceName: "test", PlanID: "plan-x", PlanName: "x", Status: "running",
		Rings: []store.RolloutRing{
			{Ring: store.Ring{Name: "Pilot", Percent: 10}, State: "soaking", AgentIDs: ids[:1], RunID: runID, StartedAt: &now},
			{Ring: store.Ring{Name: "Rest", Percent: 100}, State: "pending", AgentIDs: []string{}},
		},
		Params: json.RawMessage(`{"requested_by":"jdoe"}`), CreatedBy: "jdoe",
	})
	if err != nil {
		t.Fatal(err)
	}
	stale, _ := st.GetRingRollout(ctx, ro.ID)
	found, err := st.RunningRolloutsForRun(ctx, runID)
	if err != nil || len(found) != 1 || found[0].ID != ro.ID {
		t.Fatalf("rollouts for run: %v %+v", err, found)
	}
	if !s.haltRolloutNow(ctx, ro.ID, runID, "web-01: nginx no longer running") {
		t.Fatal("halt did not finish")
	}
	got, _ := st.GetRingRollout(ctx, ro.ID)
	if got.Status != "halted" || got.Rings[0].State != "failed" || got.HaltReason == "" {
		t.Fatalf("after a failed health check: %+v", got)
	}
	if ok, err := st.SaveRingRollout(ctx, stale); err != nil || ok {
		t.Fatalf("a stale save went through: %v %v", ok, err)
	}
	if again, _ := st.RunningRolloutsForRun(ctx, runID); len(again) != 0 {
		t.Fatalf("a halted rollout is still listed as running for the run")
	}
}
