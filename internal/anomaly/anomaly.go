// Package anomaly decides when an endpoint has moved well outside its own
// normal. It holds no state and does no I/O: the server samples metrics
// from what agents already report, keeps them in Postgres, and asks this
// package what the numbers mean. Keeping the judgement pure is what lets
// the rules (learning period, sustained window, hysteresis, severity,
// grouping) be tested without a database.
//
// The statistic is robust on purpose. A mean and standard deviation are
// dragged by exactly the outliers this exists to find, so one bad night
// would widen the band enough to hide the next one. The median and the
// median absolute deviation (MAD) are not moved by a few extreme hours.
package anomaly

import (
	"math"
	"sort"
	"time"
)

// Tuning. Each is a trade between noise and how quickly a real problem
// shows, and each is written down in docs/CONCEPTS.md.
const (
	// KOpen is how many robust standard deviations from the median a
	// value must be before it counts as outside the band.
	KOpen = 4.0
	// KClose is the inner band an open anomaly must come back inside
	// before it can close. Narrower than KOpen so a value hovering at the
	// edge does not open and close the same anomaly every few minutes.
	KClose = 3.0
	// MinBaselineHours is how many hourly medians a baseline needs before
	// the endpoint is judged against it. Until then it is learning, not
	// anomalous: a new endpoint has no normal yet.
	MinBaselineHours = 48
	// BaselineWindow is how far back the baseline looks. A lasting change
	// becomes the new normal once it fills about half of it.
	BaselineWindow = 14 * 24 * time.Hour
	// StatWindow is the trailing window each judged value is the median
	// of: one spike in a five-minute sample is not a value worth judging.
	StatWindow = time.Hour
	// Sustain is how long the smoothed value must stay outside the band,
	// in the same direction, before an anomaly opens.
	Sustain = 2 * time.Hour
	// Settle is how long it must stay back inside the inner band before
	// the anomaly closes.
	Settle = time.Hour
	// MaxGap breaks a run: an endpoint that slept for three hours did not
	// spend them outside its band.
	MaxGap = 2 * time.Hour
	// StaleAfter: with no sample this recent there is nothing current to
	// judge, so nothing opens or closes.
	StaleAfter = 2 * time.Hour
	// ExpireAfter closes an open anomaly whose endpoint stopped reporting
	// the metric. Offline is the Guide's business, not this one's.
	ExpireAfter = 24 * time.Hour
	// minRunPoints keeps two lucky points from making a run.
	minRunPoints = 3
	// madScale turns a MAD into a standard-deviation estimate for
	// normally distributed data.
	madScale = 1.4826
)

// Directions an anomaly can take.
const (
	High = "high"
	Low  = "low"
)

// Severity levels, lowest first.
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Metric is one number sampled per endpoint.
type Metric struct {
	Key   string
	Label string
	Unit  string // "%", "" for a count, "/24h"
	// Sensor is the sensor the value comes from, so a caller whose
	// content sets do not grant that sensor does not see it. Empty for a
	// value from the endpoint's own facts, which belong to no sensor.
	Sensor string
	// Floor is the band's minimum half-width, in the metric's unit, and
	// FloorRel the same as a fraction of the median. A machine whose CPU
	// sits at exactly 3% every hour has a MAD of zero; without a floor a
	// move to 5% would be "infinitely" anomalous.
	Floor    float64
	FloorRel float64
	High     bool // judged when it rises
	Low      bool // judged when it falls
	// Percent clamps sampled values to 0..100.
	Percent bool
	// Source says, per platform, where the value comes from. Shown on
	// the page so nobody has to guess what "services" means on a Mac.
	Source string
}

// Metrics are the signals judged, in display order.
var Metrics = []Metric{
	{Key: "cpu", Label: "CPU use", Unit: "%", Sensor: "performance", Floor: 15, High: true, Low: true, Percent: true,
		Source: "The performance sensor's current CPU reading, reported every minute on every platform."},
	{Key: "memory", Label: "Memory use", Unit: "%", Sensor: "performance", Floor: 10, High: true, Low: true, Percent: true,
		Source: "The performance sensor's current memory use, every minute on every platform."},
	{Key: "disk", Label: "System disk use", Unit: "%", Sensor: "performance", Floor: 5, High: true, Percent: true,
		Source: "The performance sensor's system-disk use. A sudden fill, not the slow creep of a disk that is merely full."},
	{Key: "processes", Label: "Running processes", Sensor: "processes", Floor: 25, FloorRel: 0.25, High: true, Low: true,
		Source: "How many processes the processes sensor listed, on every platform."},
	{Key: "services_failed", Label: "Failed services", Sensor: "services", Floor: 2, High: true,
		Source: "Linux: systemd units in the failed state. Windows: automatic-start services that are stopped. macOS: not available (launchctl does not say whether a job failed), so it stays at zero."},
	{Key: "reboots", Label: "Restarts in 24 hours", Unit: "/24h", Floor: 2, High: true,
		Source: "Boot times from the agent's facts, counted over the last 24 hours, on every platform. A machine that restarts on its own keeps showing up here."},
}

// Lookup returns the metric with this key.
func Lookup(key string) (Metric, bool) {
	for _, m := range Metrics {
		if m.Key == key {
			return m, true
		}
	}
	return Metric{}, false
}

// Clean makes a sampled value safe to store: nothing non-finite, and a
// percentage inside 0..100. ok is false for a value to drop.
func (m Metric) Clean(v float64) (float64, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	if m.Percent {
		v = math.Max(0, math.Min(100, v))
	} else if v < 0 {
		return 0, false
	}
	return v, true
}

// Baseline is one endpoint's normal for one metric: the median of its
// hourly medians over BaselineWindow, their MAD, and how many hours that
// covers.
type Baseline struct {
	Median float64 `json:"median"`
	MAD    float64 `json:"mad"`
	Hours  int     `json:"hours"`
}

// Ready reports whether there is enough history to judge against.
func (b Baseline) Ready() bool { return b.Hours >= MinBaselineHours }

// Compute is the baseline of these hourly medians. The server computes the
// same thing in SQL; this is the reference the integration test holds it
// to.
func Compute(hourly []float64) Baseline {
	if len(hourly) == 0 {
		return Baseline{}
	}
	med := Median(hourly)
	dev := make([]float64, len(hourly))
	for i, v := range hourly {
		dev[i] = math.Abs(v - med)
	}
	return Baseline{Median: med, MAD: Median(dev), Hours: len(hourly)}
}

// Median of vs, interpolating between the middle two like Postgres's
// percentile_cont(0.5). vs is not modified.
func Median(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	s := append([]float64(nil), vs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Band is the range a value is judged against.
type Band struct {
	Lo      float64 `json:"lo"`
	Hi      float64 `json:"hi"`
	InnerLo float64 `json:"inner_lo"`
	InnerHi float64 `json:"inner_hi"`
	// Scale is one robust standard deviation, floored, in the metric's
	// unit: deviations are measured in it.
	Scale float64 `json:"scale"`
}

// Scale is one robust standard deviation for this baseline, never less
// than the metric's floor spread over KOpen.
func (m Metric) Scale(b Baseline) float64 {
	floor := math.Max(m.Floor, m.FloorRel*math.Abs(b.Median)) / KOpen
	return math.Max(madScale*b.MAD, math.Max(floor, 1e-9))
}

// Band is where this metric's values are normal for this baseline.
func (m Metric) Band(b Baseline) Band {
	sc := m.Scale(b)
	bd := Band{Lo: b.Median - KOpen*sc, Hi: b.Median + KOpen*sc,
		InnerLo: b.Median - KClose*sc, InnerHi: b.Median + KClose*sc, Scale: sc}
	if m.Percent {
		bd.Lo, bd.InnerLo = math.Max(bd.Lo, 0), math.Max(bd.InnerLo, 0)
		bd.Hi, bd.InnerHi = math.Min(bd.Hi, 100), math.Min(bd.InnerHi, 100)
	} else {
		bd.Lo, bd.InnerLo = math.Max(bd.Lo, 0), math.Max(bd.InnerLo, 0)
	}
	return bd
}

// Z is how many robust standard deviations v is from the median.
func (m Metric) Z(b Baseline, v float64) float64 {
	return math.Abs(v-b.Median) / m.Scale(b)
}

// Sample is one stored value.
type Sample struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// Point is a smoothed value: the median of the samples in the StatWindow
// ending at At.
type Point struct {
	At   time.Time
	Stat float64
}

// Smooth turns samples (in any order) into trailing-window medians, one
// per sample.
func Smooth(samples []Sample, window time.Duration) []Point {
	s := append([]Sample(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i].At.Before(s[j].At) })
	out := make([]Point, 0, len(s))
	start := 0
	var buf []float64
	for i, x := range s {
		for start < i && !s[start].At.After(x.At.Add(-window)) {
			start++
		}
		buf = buf[:0]
		for _, y := range s[start : i+1] {
			buf = append(buf, y.Value)
		}
		out = append(out, Point{At: x.At, Stat: Median(buf)})
	}
	return out
}

// Open is what the caller knows about an anomaly already open for this
// endpoint and metric.
type Open struct {
	Direction string
	StartedAt time.Time
	PeakValue float64
	PeakZ     float64
}

// Action is what Evaluate decided.
type Action int

const (
	None   Action = iota // nothing to record (learning, quiet, or no current data)
	Start                // open a new anomaly
	Update               // still open: refresh its value and peak
	Close                // it is over
)

// Decision is Evaluate's answer.
type Decision struct {
	Action    Action
	Direction string
	At        time.Time // Start: when the run began; Close: when it ended
	Value     float64   // the latest smoothed value
	Z         float64
	PeakValue float64
	PeakZ     float64
	// NoData is set on a Close because the metric stopped arriving
	// rather than because it came back.
	NoData bool
}

// Evaluate decides what the samples mean for one endpoint and metric.
// open is nil when no anomaly is open.
func Evaluate(m Metric, b Baseline, samples []Sample, open *Open, now time.Time) Decision {
	pts := Smooth(samples, StatWindow)
	if len(pts) == 0 {
		if open != nil && now.Sub(open.StartedAt) > ExpireAfter {
			return Decision{Action: Close, Direction: open.Direction, At: now, NoData: true, PeakValue: open.PeakValue, PeakZ: open.PeakZ}
		}
		return Decision{}
	}
	last := pts[len(pts)-1]
	if now.Sub(last.At) > StaleAfter {
		if open != nil && now.Sub(last.At) > ExpireAfter {
			return Decision{Action: Close, Direction: open.Direction, At: last.At, NoData: true, PeakValue: open.PeakValue, PeakZ: open.PeakZ}
		}
		return Decision{}
	}
	if !b.Ready() {
		return Decision{}
	}
	band := m.Band(b)
	dir := func(p Point) string {
		switch {
		case m.High && p.Stat > band.Hi:
			return High
		case m.Low && p.Stat < band.Lo:
			return Low
		}
		return ""
	}

	if open == nil {
		d := dir(last)
		if d == "" {
			return Decision{}
		}
		first := runBack(pts, func(p Point) bool { return dir(p) == d })
		if len(pts)-first < minRunPoints || last.At.Sub(pts[first].At) < Sustain {
			return Decision{}
		}
		pv := pts[first].Stat
		for _, p := range pts[first:] {
			if (d == High && p.Stat > pv) || (d == Low && p.Stat < pv) {
				pv = p.Stat
			}
		}
		return Decision{Action: Start, Direction: d, At: pts[first].At, Value: last.Stat, Z: m.Z(b, last.Stat),
			PeakValue: pv, PeakZ: m.Z(b, pv)}
	}

	inside := func(p Point) bool {
		if open.Direction == High {
			return p.Stat <= band.InnerHi
		}
		return p.Stat >= band.InnerLo
	}
	if inside(last) {
		first := runBack(pts, inside)
		if len(pts)-first >= 2 && last.At.Sub(pts[first].At) >= Settle {
			return Decision{Action: Close, Direction: open.Direction, At: pts[first].At, Value: last.Stat,
				Z: m.Z(b, last.Stat), PeakValue: open.PeakValue, PeakZ: open.PeakZ}
		}
	}
	dec := Decision{Action: Update, Direction: open.Direction, Value: last.Stat, Z: m.Z(b, last.Stat),
		PeakValue: open.PeakValue, PeakZ: open.PeakZ}
	// Only a value further out in the anomaly's own direction is a new
	// peak; a high anomaly that dips does not get a "low" peak.
	beyond := (open.Direction == High && last.Stat > band.Hi) || (open.Direction == Low && last.Stat < band.Lo)
	if beyond && dec.Z > dec.PeakZ {
		dec.PeakValue, dec.PeakZ = last.Stat, dec.Z
	}
	return dec
}

// runBack walks back from the newest point while ok holds and points are
// no more than MaxGap apart, and returns the index of the run's first
// point.
func runBack(pts []Point, ok func(Point) bool) int {
	first := len(pts) - 1
	for i := len(pts) - 2; i >= 0; i-- {
		if !ok(pts[i]) || pts[i+1].At.Sub(pts[i].At) > MaxGap {
			break
		}
		first = i
	}
	return first
}

// Severity is the level and ranking score of an anomaly that reached
// peakZ and has lasted d. The score grows with the deviation (capped so
// one absurd reading does not outrank everything) and with time, up to
// three days: a problem that has gone on for a day matters more than one
// that started an hour ago.
func Severity(peakZ float64, d time.Duration) (level string, score float64) {
	z := math.Min(peakZ, 50)
	hours := math.Max(0, math.Min(d.Hours(), 72))
	score = math.Round(z*(1+hours/24)*10) / 10
	lv := 0
	switch {
	case z >= 20:
		lv = 3
	case z >= 10:
		lv = 2
	case z >= 6:
		lv = 1
	}
	if d >= 24*time.Hour && lv < 3 {
		lv++
	}
	return []string{SevLow, SevMedium, SevHigh, SevCritical}[lv], score
}

// SeverityRank orders levels, for "the worst of these".
func SeverityRank(level string) int {
	switch level {
	case SevCritical:
		return 3
	case SevHigh:
		return 2
	case SevMedium:
		return 1
	}
	return 0
}
