package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
)

func TestNetworkSurveysRoundTrip(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	n := NetworkSurvey{ID: idgen.New("nsv-"), Name: "line 3", AgentIDs: []string{"agt-a"}, Subnets: []string{"10.40.7.0/24"},
		Protocols: []string{"snmp", "ipp"}, PacketsPerSecond: 20, Concurrency: 8, TimeoutMillis: 1500, BudgetSeconds: 60,
		SNMPVersion: "2c", SNMPSecretEnc: []byte{1, 2, 3}, CreatedBy: "alice"}
	if err := s.SaveNetworkSurvey(ctx, n); err != nil {
		t.Fatal(err)
	}
	n.Name, n.CreatedBy, n.Enabled = "line 3 (edited)", "bob", true
	if err := s.SaveNetworkSurvey(ctx, n); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNetworkSurvey(ctx, n.ID)
	if err != nil || got == nil {
		t.Fatalf("%v %v", got, err)
	}
	if got.Name != "line 3 (edited)" || !got.Enabled || got.CreatedBy != "alice" || string(got.SNMPSecretEnc) != "\x01\x02\x03" || got.LastRunAt != nil {
		t.Fatalf("%+v", got)
	}

	run := NetworkSurveyRun{ID: idgen.New("nsr-"), SurveyID: n.ID, AgentID: "agt-a", Status: "dispatched", Subnets: n.Subnets, BudgetSeconds: 1}
	if err := s.CreateNetworkSurveyRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.SurveyRunActive(ctx, n.ID); !active {
		t.Fatal("a dispatched run is not active")
	}
	if err := s.SetNetworkSurveyRunStatus(ctx, run.ID, "running", "", false); err != nil {
		t.Fatal(err)
	}

	// A device first known by address, then by MAC, is one row that keeps
	// its first sighting. Fresh addresses each run: devices outlive surveys.
	suffix := time.Now().UnixNano()
	mac := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", byte(suffix>>32), byte(suffix>>24), byte(suffix>>16), byte(suffix>>8), byte(suffix))
	ip := fmt.Sprintf("10.%d.%d.%d", byte(suffix>>16), byte(suffix>>8), byte(suffix)|1)
	first := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	run.Status, run.DevicesFound, run.Summary = "succeeded", 1, json.RawMessage(`{"discarded":0}`)
	byIP := NetworkSurveyDevice{Key: "ip:" + ip, IP: ip, DeviceType: "printer", Device: json.RawMessage(`{"ip":"10.40.7.20"}`), AgentID: "agt-a", SurveyID: n.ID}
	if err := s.FinishNetworkSurveyRun(ctx, run, []NetworkSurveyDevice{byIP}, first); err != nil {
		t.Fatal(err)
	}
	byMAC := NetworkSurveyDevice{Key: mac, MAC: mac, IP: ip, DeviceType: "printer", Device: json.RawMessage(`{"ip":"10.40.7.20"}`), AgentID: "agt-a", SurveyID: n.ID}
	if err := s.FinishNetworkSurveyRun(ctx, run, []NetworkSurveyDevice{byMAC}, time.Now()); err != nil {
		t.Fatal(err)
	}
	devs, err := s.ListNetworkSurveyDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []NetworkSurveyDevice
	for _, d := range devs {
		if d.SurveyID == n.ID {
			mine = append(mine, d)
		}
	}
	if len(mine) != 1 || mine[0].Key != mac || !mine[0].FirstSeen.Equal(first) {
		t.Fatalf("%+v", mine)
	}
	r, err := s.GetNetworkSurveyRun(ctx, run.ID)
	if err != nil || r.Status != "succeeded" || r.FinishedAt == nil || r.DevicesFound != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// A finished run is not moved by a late status.
	if err := s.SetNetworkSurveyRunStatus(ctx, run.ID, "no_response", "late", true); err != nil {
		t.Fatal(err)
	}
	if r, _ = s.GetNetworkSurveyRun(ctx, run.ID); r.Status != "succeeded" {
		t.Fatalf("overwritten: %s", r.Status)
	}

	// A run silent past its budget and the grace is timed out.
	stale := NetworkSurveyRun{ID: idgen.New("nsr-"), SurveyID: n.ID, AgentID: "agt-a", Status: "running", Subnets: n.Subnets, BudgetSeconds: 1}
	if err := s.CreateNetworkSurveyRun(ctx, stale); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := s.ExpireNetworkSurveyRuns(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if r, _ = s.GetNetworkSurveyRun(ctx, stale.ID); r.Status != "timed_out" {
		t.Fatalf("stale run: %s", r.Status)
	}

	if ok, err := s.DeleteNetworkSurvey(ctx, n.ID); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if r, _ = s.GetNetworkSurveyRun(ctx, run.ID); r != nil {
		t.Fatal("runs outlived their survey")
	}
	// What it found stays in Discover.
	devs, _ = s.ListNetworkSurveyDevices(ctx)
	kept := false
	for _, d := range devs {
		kept = kept || d.Key == mac
	}
	if !kept {
		t.Fatal("deleting the survey removed its devices")
	}
}
