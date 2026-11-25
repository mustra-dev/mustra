package store

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/anomaly"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The baseline SQL computes what anomaly.Compute does, from the hourly
// medians the rollup writes.
func TestAnomalyBaselineMatchesReference(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	agent := testAgent(t, s)
	// A timeline of its own, years back, so pruning here cannot touch
	// rows another test is writing in the present at the same time.
	now := time.Date(2020, 3, 1, 12, 0, 0, 0, time.UTC)
	var samples []AnomalySample
	var hourly []float64
	for h := 60; h >= 1; h-- {
		hour := now.Add(-time.Duration(h) * time.Hour)
		// Three samples an hour whose median is a known value, with
		// some hours far off so median and MAD are not trivial.
		mid := 10 + float64(h%7)
		if h%17 == 0 {
			mid = 80
		}
		for i, v := range []float64{mid - 3, mid, mid + 40} {
			samples = append(samples, AnomalySample{AgentID: agent, Metric: "cpu", At: hour.Add(time.Duration(i*10) * time.Minute), Value: v})
		}
		hourly = append(hourly, mid)
	}
	if err := s.InsertAnomalySamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	// Inserting the same samples again is a no-op.
	if err := s.InsertAnomalySamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	if err := s.RollUpAnomalyHours(ctx, now.Add(-61*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	hours, err := s.ListAnomalyHours(ctx, agent, "cpu", now.Add(-61*time.Hour))
	if err != nil || len(hours) != 60 || hours[0].N != 3 {
		t.Fatalf("hours: %d %+v %v", len(hours), hours[:min(1, len(hours))], err)
	}
	if err := s.RecomputeAnomalyBaselines(ctx, now.Add(-anomaly.BaselineWindow), now); err != nil {
		t.Fatal(err)
	}
	bs, err := s.ListAnomalyBaselines(ctx, agent)
	if err != nil || len(bs) != 1 {
		t.Fatalf("baselines %+v %v", bs, err)
	}
	want := anomaly.Compute(hourly)
	if math.Abs(bs[0].Median-want.Median) > 1e-9 || math.Abs(bs[0].MAD-want.MAD) > 1e-9 || bs[0].Hours != want.Hours {
		t.Fatalf("SQL baseline %+v, reference %+v", bs[0], want)
	}

	// Retention: past their keep, samples, hours and closed anomalies go;
	// an open anomaly stays however old.
	open := Anomaly{ID: "anom-ret-open-" + agent, AgentID: agent, Metric: "cpu", Direction: "high", StartedAt: now.Add(-50 * time.Hour),
		LastSeenAt: now, Severity: "low"}
	if ok, err := s.OpenAnomaly(ctx, open); err != nil || !ok {
		t.Fatalf("open: %v %v", ok, err)
	}
	if ok, _ := s.OpenAnomaly(ctx, Anomaly{ID: "anom-ret-dup-" + agent, AgentID: agent, Metric: "cpu", Direction: "low",
		StartedAt: now, LastSeenAt: now, Severity: "low"}); ok {
		t.Fatal("a second open anomaly for the same endpoint and metric was recorded")
	}
	shut := Anomaly{ID: "anom-ret-closed-" + agent, AgentID: agent, Metric: "memory", Direction: "high", StartedAt: now.Add(-50 * time.Hour),
		LastSeenAt: now.Add(-49 * time.Hour), Severity: "low"}
	if _, err := s.OpenAnomaly(ctx, shut); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseAnomaly(ctx, shut.ID, now.Add(-48*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	keep := AnomalyRetention{Samples: 24 * time.Hour, Hours: 30 * time.Hour, Boots: time.Hour, Closed: 24 * time.Hour, ExpiredSuppressions: time.Hour}
	if err := s.PruneAnomalyData(ctx, now, keep); err != nil {
		t.Fatal(err)
	}
	left, err := s.ListAnomalySamples(ctx, now.Add(-100*time.Hour), agent, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range left {
		if x.At.Before(now.Add(-24 * time.Hour)) {
			t.Fatalf("sample from %v survived a 24h retention", x.At)
		}
	}
	if len(left) != 24*3 {
		t.Fatalf("%d samples left, want the last day's 72", len(left))
	}
	if hours, _ := s.ListAnomalyHours(ctx, agent, "cpu", now.Add(-100*time.Hour)); len(hours) != 30 {
		t.Fatalf("%d hours left, want 30", len(hours))
	}
	if x, _ := s.GetAnomaly(ctx, shut.ID); x != nil {
		t.Fatal("a closed anomaly survived its retention")
	}
	if x, _ := s.GetAnomaly(ctx, open.ID); x == nil {
		t.Fatal("an open anomaly was pruned")
	}
}

// Processes and failed services are counted from the snapshots in SQL; a
// snapshot that is not a list, or holds junk, costs only itself.
func TestAnomalyInventorySampling(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	linux, windows, junk := testAgent(t, s), testAgent(t, s), testAgent(t, s)
	at := time.Now().Add(-time.Minute)
	put := func(id, sensor, data string) {
		if err := s.UpsertSensorData(ctx, id, sensor, at, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	put(linux, "processes", `[{"pid":1,"name":"init"},{"pid":2,"name":"sshd"},{"pid":3,"name":"nginx"}]`)
	put(linux, "services", `[{"name":"nginx","status":"running"},{"name":"db","status":"failed"},{"name":"x","status":"dead"}]`)
	put(windows, "services", `[{"name":"Spooler","status":"stopped","start_type":"automatic"},{"name":"W32Time","status":"stopped","start_type":"manual"},{"name":"WinRM","status":"running","start_type":"automatic"}]`)
	put(junk, "services", `{"not":"a list"}`)
	put(junk, "processes", `[1, "two", null]`)
	if err := s.SampleInventoryMetrics(ctx, at.Add(-time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Twice is still one sample per snapshot.
	if err := s.SampleInventoryMetrics(ctx, at.Add(-time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	get := func(id, metric string) []AnomalySample {
		xs, err := s.ListAnomalySamples(ctx, at.Add(-time.Hour), id, metric)
		if err != nil {
			t.Fatal(err)
		}
		return xs
	}
	if xs := get(linux, "processes"); len(xs) != 1 || xs[0].Value != 3 {
		t.Fatalf("linux processes %+v", xs)
	}
	if xs := get(linux, "services_failed"); len(xs) != 1 || xs[0].Value != 1 {
		t.Fatalf("linux failed services %+v", xs)
	}
	if xs := get(windows, "services_failed"); len(xs) != 1 || xs[0].Value != 1 {
		t.Fatalf("windows failed services %+v", xs)
	}
	if xs := get(junk, "services_failed"); len(xs) != 0 {
		t.Fatalf("a non-list services snapshot was sampled: %+v", xs)
	}
	if xs := get(junk, "processes"); len(xs) != 1 || xs[0].Value != 3 {
		t.Fatalf("junk processes %+v", xs)
	}
}

// A boot time that wobbles by a second between facts is one boot, and
// the reboots sample counts boots in the day before.
func TestAnomalyRebootsAreCountedOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	agent := testAgent(t, s)
	start := time.Now().Truncate(time.Second)
	firstBoot, secondBoot := start.Add(-3*time.Hour), start.Add(10*time.Minute)
	for i, c := range []struct {
		at   time.Time
		boot time.Time
		want float64
	}{
		{start, firstBoot, 1},
		{start.Add(5 * time.Minute), firstBoot.Add(time.Second), 1}, // the same boot, a second off
		{start.Add(15 * time.Minute), secondBoot, 2},
	} {
		f := proto.Facts{AgentID: agent, Timestamp: c.at, Hostname: "ts-host", OS: "linux", UptimeSec: uint64(c.at.Sub(c.boot).Seconds())}
		if err := s.RecordFacts(ctx, f); err != nil {
			t.Fatal(err)
		}
		if err := s.SampleReboots(ctx, c.at); err != nil {
			t.Fatal(err)
		}
		xs, err := s.ListAnomalySamples(ctx, c.at, agent, "reboots")
		if err != nil || len(xs) != 1 || xs[0].Value != c.want {
			t.Fatalf("step %d: reboots %+v %v, want %v", i, xs, err, c.want)
		}
	}
}
