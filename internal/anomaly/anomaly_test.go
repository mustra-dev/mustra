package anomaly

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// series is one sample every five minutes from start for d, valued by f
// (given the offset from start).
func series(start time.Time, d time.Duration, f func(time.Duration) float64) []Sample {
	var out []Sample
	for off := time.Duration(0); off < d; off += 5 * time.Minute {
		out = append(out, Sample{At: start.Add(off), Value: f(off)})
	}
	return out
}

func cpu() Metric { m, _ := Lookup("cpu"); return m }

// A quiet machine: CPU around 20%, a two-point MAD, plenty of history.
var quiet = Baseline{Median: 20, MAD: 2, Hours: 14 * 24}

func TestComputeMedianAndMAD(t *testing.T) {
	b := Compute([]float64{1, 2, 3, 4, 100})
	if b.Median != 3 || b.MAD != 1 || b.Hours != 5 {
		t.Fatalf("baseline %+v, want median 3 MAD 1 over 5", b)
	}
	// Even count interpolates, as percentile_cont does.
	if m := Median([]float64{4, 1, 3, 2}); m != 2.5 {
		t.Fatalf("median %v, want 2.5", m)
	}
	// One absurd hour does not drag the baseline the way a mean would.
	vals := make([]float64, 100)
	for i := range vals {
		vals[i] = 20 + float64(i%5)
	}
	vals[50] = 1e6
	if b := Compute(vals); b.Median > 23 || b.MAD > 2 {
		t.Fatalf("baseline moved by an outlier: %+v", b)
	}
}

func TestBandFloorAndClamp(t *testing.T) {
	m := cpu()
	// A MAD of zero still leaves the floor: 15 points wide at KOpen.
	b := m.Band(Baseline{Median: 3, MAD: 0, Hours: 100})
	if math.Abs(b.Hi-18) > 1e-9 || b.Lo != 0 {
		t.Fatalf("band %+v, want hi 18 and lo clamped to 0", b)
	}
	// A wide MAD wins over the floor, and a percentage never passes 100.
	b = m.Band(Baseline{Median: 90, MAD: 10, Hours: 100})
	if b.Hi != 100 || b.InnerHi != 100 {
		t.Fatalf("band %+v, want clamped to 100", b)
	}
	if v, ok := m.Clean(140); !ok || v != 100 {
		t.Fatalf("clean 140 = %v %v", v, ok)
	}
	if _, ok := m.Clean(math.NaN()); ok {
		t.Fatal("NaN kept")
	}
	p, _ := Lookup("processes")
	if _, ok := p.Clean(-1); ok {
		t.Fatal("negative count kept")
	}
	// The relative floor: 25% of 400 processes is 100.
	if b := p.Band(Baseline{Median: 400, MAD: 0, Hours: 100}); math.Abs(b.Hi-500) > 1e-9 {
		t.Fatalf("processes band %+v, want hi 500", b)
	}
}

func TestLearningIsNotAnomalous(t *testing.T) {
	young := quiet
	young.Hours = MinBaselineHours - 1
	s := series(t0, 6*time.Hour, func(time.Duration) float64 { return 99 })
	if d := Evaluate(cpu(), young, s, nil, s[len(s)-1].At); d.Action != None {
		t.Fatalf("a learning endpoint was judged: %+v", d)
	}
	young.Hours = MinBaselineHours
	if d := Evaluate(cpu(), young, s, nil, s[len(s)-1].At); d.Action != Start {
		t.Fatalf("a ready baseline was not judged: %+v", d)
	}
}

// The value must stay outside the band for Sustain before anything
// opens, and the anomaly starts when the smoothed value left the band.
func TestOpensOnlyWhenSustained(t *testing.T) {
	spike := t0.Add(3 * time.Hour)
	f := func(off time.Duration) float64 {
		if t0.Add(off).Before(spike) {
			return 20
		}
		return 90
	}
	all := series(t0, 8*time.Hour, f)
	upTo := func(at time.Time) []Sample {
		var out []Sample
		for _, s := range all {
			if !s.At.After(at) {
				out = append(out, s)
			}
		}
		return out
	}
	// The trailing-hour median crosses after about half an hour of high
	// samples; two hours after that it opens, and not before.
	for _, c := range []struct {
		at   time.Duration
		want Action
	}{{time.Hour, None}, {2 * time.Hour, None}, {2*time.Hour + 20*time.Minute, None}, {2*time.Hour + 40*time.Minute, Start}} {
		now := spike.Add(c.at)
		d := Evaluate(cpu(), quiet, upTo(now), nil, now)
		if d.Action != c.want {
			t.Fatalf("%v after the spike: action %v, want %v (%+v)", c.at, d.Action, c.want, d)
		}
		if d.Action == Start {
			if d.Direction != High || d.PeakValue != 90 || d.PeakZ < 15 {
				t.Fatalf("opened %+v", d)
			}
			if d.At.Before(spike) || d.At.After(spike.Add(40*time.Minute)) {
				t.Fatalf("started at %v, want shortly after %v", d.At, spike)
			}
		}
	}
}

func TestSingleSpikeAndFlappingNeverOpen(t *testing.T) {
	// One five-minute reading at 100% every hour: the hourly median never
	// moves.
	s := series(t0, 12*time.Hour, func(off time.Duration) float64 {
		if off%time.Hour == 0 {
			return 100
		}
		return 20
	})
	for i := 1; i <= len(s); i++ {
		if d := Evaluate(cpu(), quiet, s[:i], nil, s[i-1].At); d.Action != None {
			t.Fatalf("spikes opened an anomaly at %v: %+v", s[i-1].At, d)
		}
	}
	// An hour and a half bad, an hour and a half good, all day: each bad
	// run is shorter than Sustain.
	s = series(t0, 24*time.Hour, func(off time.Duration) float64 {
		if (off/(90*time.Minute))%2 == 0 {
			return 95
		}
		return 20
	})
	for i := 1; i <= len(s); i++ {
		if d := Evaluate(cpu(), quiet, s[:i], nil, s[i-1].At); d.Action != None {
			t.Fatalf("a flapping value opened an anomaly at %v: %+v", s[i-1].At, d)
		}
	}
}

// Once open, an anomaly closes only after Settle back inside the inner
// band; hovering between the inner and outer band keeps it open.
func TestClosesWithHysteresis(t *testing.T) {
	open := &Open{Direction: High, StartedAt: t0, PeakValue: 90, PeakZ: 18.7}
	band := cpu().Band(quiet) // hi 35, inner hi 31.25
	hover := series(t0, 5*time.Hour, func(time.Duration) float64 { return (band.Hi + band.InnerHi) / 2 })
	if d := Evaluate(cpu(), quiet, hover, open, hover[len(hover)-1].At); d.Action != Update {
		t.Fatalf("hovering at the edge: %+v, want it kept open", d)
	}
	// Nor does hovering reopen anything when nothing is open: it is inside
	// the outer band.
	if d := Evaluate(cpu(), quiet, hover, nil, hover[len(hover)-1].At); d.Action != None {
		t.Fatalf("hovering opened: %+v", d)
	}
	back := t0.Add(4 * time.Hour)
	s := series(t0, 6*time.Hour, func(off time.Duration) float64 {
		if t0.Add(off).Before(back) {
			return 90
		}
		return 20
	})
	at := func(d time.Duration) []Sample {
		var out []Sample
		for _, x := range s {
			if !x.At.After(back.Add(d)) {
				out = append(out, x)
			}
		}
		return out
	}
	if d := Evaluate(cpu(), quiet, at(time.Hour), open, back.Add(time.Hour)); d.Action != Update {
		t.Fatalf("an hour after it came back (smoothed for half of it): %+v, want still open", d)
	}
	d := Evaluate(cpu(), quiet, at(100*time.Minute), open, back.Add(100*time.Minute))
	if d.Action != Close || d.NoData {
		t.Fatalf("well after it came back: %+v, want closed", d)
	}
	if d.At.Before(back) || d.At.After(back.Add(40*time.Minute)) {
		t.Fatalf("closed at %v, want shortly after %v", d.At, back)
	}
}

func TestPeakFollowsDirection(t *testing.T) {
	open := &Open{Direction: High, StartedAt: t0, PeakValue: 50, PeakZ: cpu().Z(quiet, 50)}
	s := series(t0, 3*time.Hour, func(time.Duration) float64 { return 80 })
	d := Evaluate(cpu(), quiet, s, open, s[len(s)-1].At)
	if d.Action != Update || d.PeakValue != 80 {
		t.Fatalf("%+v, want peak raised to 80", d)
	}
	s = series(t0, 3*time.Hour, func(time.Duration) float64 { return 40 })
	d = Evaluate(cpu(), quiet, s, &Open{Direction: High, StartedAt: t0, PeakValue: 80, PeakZ: cpu().Z(quiet, 80)}, s[len(s)-1].At)
	if d.Action != Update || d.PeakValue != 80 {
		t.Fatalf("%+v, want peak kept at 80", d)
	}
}

func TestStaleDataNeitherOpensNorCloses(t *testing.T) {
	s := series(t0, 6*time.Hour, func(time.Duration) float64 { return 95 })
	last := s[len(s)-1].At
	if d := Evaluate(cpu(), quiet, s, nil, last.Add(3*time.Hour)); d.Action != None {
		t.Fatalf("judged old data: %+v", d)
	}
	open := &Open{Direction: High, StartedAt: t0, PeakValue: 95, PeakZ: 20}
	if d := Evaluate(cpu(), quiet, s, open, last.Add(3*time.Hour)); d.Action != None {
		t.Fatalf("an open anomaly changed on old data: %+v", d)
	}
	d := Evaluate(cpu(), quiet, s, open, last.Add(ExpireAfter+time.Minute))
	if d.Action != Close || !d.NoData || !d.At.Equal(last) {
		t.Fatalf("a day without data: %+v, want closed for no data at the last sample", d)
	}
	if d := Evaluate(cpu(), quiet, nil, open, t0.Add(ExpireAfter+time.Hour)); d.Action != Close || !d.NoData {
		t.Fatalf("no samples at all: %+v", d)
	}
}

func TestDirectionsAMetricIgnores(t *testing.T) {
	disk, _ := Lookup("disk")
	b := Baseline{Median: 70, MAD: 1, Hours: 200}
	s := series(t0, 6*time.Hour, func(time.Duration) float64 { return 10 }) // a big clean-up
	if d := Evaluate(disk, b, s, nil, s[len(s)-1].At); d.Action != None {
		t.Fatalf("a disk emptying opened: %+v", d)
	}
	s = series(t0, 6*time.Hour, func(time.Duration) float64 { return 99 })
	if d := Evaluate(disk, b, s, nil, s[len(s)-1].At); d.Action != Start || d.Direction != High {
		t.Fatalf("a disk filling: %+v", d)
	}
	// CPU falling to nothing is judged: a service that died stops using it.
	s = series(t0, 6*time.Hour, func(time.Duration) float64 { return 0 })
	if d := Evaluate(cpu(), Baseline{Median: 60, MAD: 3, Hours: 200}, s, nil, s[len(s)-1].At); d.Action != Start || d.Direction != Low {
		t.Fatalf("CPU falling: %+v", d)
	}
}

// A sample gap longer than MaxGap breaks a run: an endpoint asleep for
// the night was not outside its band all night.
func TestGapBreaksRun(t *testing.T) {
	a := series(t0, 70*time.Minute, func(time.Duration) float64 { return 95 })
	b := series(t0.Add(5*time.Hour), 70*time.Minute, func(time.Duration) float64 { return 95 })
	s := append(a, b...)
	if d := Evaluate(cpu(), quiet, s, nil, s[len(s)-1].At); d.Action != None {
		t.Fatalf("two short runs either side of a gap opened: %+v", d)
	}
}

func TestSeverity(t *testing.T) {
	for _, c := range []struct {
		z    float64
		d    time.Duration
		want string
	}{
		{4.5, time.Hour, SevLow},
		{7, time.Hour, SevMedium},
		{12, time.Hour, SevHigh},
		{25, time.Hour, SevCritical},
		{4.5, 30 * time.Hour, SevMedium}, // a day long bumps it one level
		{25, 30 * time.Hour, SevCritical},
	} {
		if lv, _ := Severity(c.z, c.d); lv != c.want {
			t.Errorf("z %v for %v: %s, want %s", c.z, c.d, lv, c.want)
		}
	}
	_, short := Severity(10, time.Hour)
	_, long := Severity(10, 48*time.Hour)
	_, capped := Severity(1e9, 1000*time.Hour)
	if !(long > short) || capped != 200 {
		t.Fatalf("scores short %v long %v capped %v", short, long, capped)
	}
}

func TestGroupingAndRanking(t *testing.T) {
	items := []Item{
		// One critical endpoint...
		{ID: "a1", AgentID: "e1", Metric: "memory", Direction: High, Level: SevCritical, Score: 40},
		// ...against the same CPU problem on four, three after one change.
		{ID: "c1", AgentID: "e2", Metric: "cpu", Direction: High, Level: SevLow, Score: 12, Change: "Install Foo 2.0"},
		{ID: "c2", AgentID: "e3", Metric: "cpu", Direction: High, Level: SevMedium, Score: 14, Change: "Install Foo 2.0"},
		{ID: "c3", AgentID: "e4", Metric: "cpu", Direction: High, Level: SevLow, Score: 10, Change: "Install Foo 2.0"},
		{ID: "c4", AgentID: "e5", Metric: "cpu", Direction: High, Level: SevLow, Score: 9, Change: "Update Bar"},
		// The other direction is another group.
		{ID: "l1", AgentID: "e6", Metric: "cpu", Direction: Low, Level: SevLow, Score: 5, Change: "Update Bar"},
		// Acknowledged: listed, but adds nothing to the rank.
		{ID: "q1", AgentID: "e7", Metric: "disk", Direction: High, Level: SevCritical, Score: 100, Quiet: true},
	}
	g := GroupItems(items)
	if len(g) != 4 {
		t.Fatalf("%d groups: %+v", len(g), g)
	}
	if g[0].Key != "cpu-high" || g[0].Endpoints != 4 || g[0].Rank != 45 || g[0].Level != SevMedium {
		t.Fatalf("first group %+v, want cpu-high, 4 endpoints, rank 45", g[0])
	}
	if g[0].Change != "Install Foo 2.0" || g[0].ChangeEndpoints != 3 {
		t.Fatalf("shared change %q on %d", g[0].Change, g[0].ChangeEndpoints)
	}
	if g[1].Key != "memory-high" || g[2].Key != "cpu-low" || g[3].Key != "disk-high" {
		t.Fatalf("order %s %s %s", g[1].Key, g[2].Key, g[3].Key)
	}
	// One endpoint's change is not a pattern.
	if g[2].Change != "" {
		t.Fatalf("single-endpoint change reported: %q", g[2].Change)
	}
	if g[3].Active != 0 || g[3].Rank != 0 || g[3].Level != SevCritical {
		t.Fatalf("acknowledged group %+v", g[3])
	}
}
