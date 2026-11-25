package saasmon

import (
	"math"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The experience score, 0 to 100, for one app on one endpoint or across
// the fleet over a period. It is computed from the period's summed
// histograms and counters, never by averaging other scores: the fleet's
// score is that of every page load in the fleet, so one endpoint with two
// page loads cannot weigh as much as one with two thousand.
//
//	score = 100 × (0.30·ramp(p75 TTFB,  800 ms, 1800 ms)
//	             + 0.30·ramp(p75 load, 3000 ms, 8000 ms)
//	             + 0.30·ramp(error rate, 1 %, 10 %)
//	             + 0.10·ramp(JS errors per page load, 1, 5))
//
// ramp(v, good, poor) is 1 at or below good, 0 at or above poor, and
// linear between. The TTFB thresholds are Core Web Vitals' own; the load
// thresholds are looser, because a SaaS app's load event waits for far
// more than its first paint. The error rate is main-frame 5xx responses,
// main-frame loads that failed outright, and XHR/fetch 5xx and failures,
// over main-frame loads plus XHR/fetch requests. 4xx responses are shown
// but not scored: a signed-out API answering 401 is how many apps work.
// JS errors weigh least, since many pages throw harmlessly all day.
//
// Below MinNavigations page loads there is no score: two slow loads say
// nothing about an app.

// Thresholds, in milliseconds for timings and as fractions for rates.
const (
	TTFBGoodMs      = 800
	TTFBPoorMs      = 1800
	LoadGoodMs      = 3000
	LoadPoorMs      = 8000
	ErrorRateGood   = 0.01
	ErrorRatePoor   = 0.10
	JSPerNavGood    = 1.0
	JSPerNavPoor    = 5.0
	MinNavigations  = 5
	weightTTFB      = 0.30
	weightLoad      = 0.30
	weightErrors    = 0.30
	weightJSErrors  = 0.10
	BandGoodAtLeast = 85
	BandFairAtLeast = 60
)

// Totals are summed aggregates.
type Totals struct {
	Navigations int64   `json:"navigations"`
	Nav4xx      int64   `json:"nav_4xx"`
	Nav5xx      int64   `json:"nav_5xx"`
	NavFailed   int64   `json:"nav_failed"`
	Requests    int64   `json:"requests"`
	Req4xx      int64   `json:"req_4xx"`
	Req5xx      int64   `json:"req_5xx"`
	ReqFailed   int64   `json:"req_failed"`
	JSErrors    int64   `json:"js_errors"`
	TTFBHist    []int64 `json:"-"`
	DCLHist     []int64 `json:"-"`
	LoadHist    []int64 `json:"-"`
}

// Add sums one aggregate into t.
func (t *Totals) Add(a proto.SaaSAggregate) {
	t.Navigations += int64(a.Navigations)
	t.Nav4xx += int64(a.Nav4xx)
	t.Nav5xx += int64(a.Nav5xx)
	t.NavFailed += int64(a.NavFailed)
	t.Requests += int64(a.Requests)
	t.Req4xx += int64(a.Req4xx)
	t.Req5xx += int64(a.Req5xx)
	t.ReqFailed += int64(a.ReqFailed)
	t.JSErrors += int64(a.JSErrors)
	t.TTFBHist = addHist64(t.TTFBHist, a.TTFBHist)
	t.DCLHist = addHist64(t.DCLHist, a.DCLHist)
	t.LoadHist = addHist64(t.LoadHist, a.LoadHist)
}

func addHist64(into []int64, h []int) []int64 {
	if len(into) < proto.SaaSHistogramLen {
		into = append(into, make([]int64, proto.SaaSHistogramLen-len(into))...)
	}
	for i, c := range h {
		if i < len(into) {
			into[i] += int64(c)
		}
	}
	return into
}

// Percentile estimates the p-th percentile (0 < p ≤ 1), in milliseconds,
// of a histogram over proto.SaaSBucketsMs, interpolating linearly inside
// the bucket the rank falls in. The estimate never leaves that bucket, so
// whether it is above or below a bucket bound — and every threshold above
// is one — is exact. Ranks in the overflow bucket report its lower bound.
// ok is false for an empty histogram.
func Percentile(hist []int64, p float64) (ms float64, ok bool) {
	var total int64
	for _, c := range hist {
		total += c
	}
	if total == 0 || p <= 0 {
		return 0, false
	}
	rank := p * float64(total)
	var cum float64
	for i, c := range hist {
		if c == 0 {
			continue
		}
		next := cum + float64(c)
		if next >= rank {
			lower := 0.0
			if i > 0 {
				lower = float64(proto.SaaSBucketsMs[i-1])
			}
			if i >= len(proto.SaaSBucketsMs) {
				return lower, true
			}
			upper := float64(proto.SaaSBucketsMs[i])
			return lower + (upper-lower)*(rank-cum)/float64(c), true
		}
		cum = next
	}
	return float64(proto.SaaSBucketsMs[len(proto.SaaSBucketsMs)-1]), true
}

// Result is a scored Totals.
type Result struct {
	// Score is 0-100; nil when there were fewer than MinNavigations loads.
	Score *int `json:"score"`
	// Band is good, fair, poor, or no_data.
	Band        string   `json:"band"`
	TTFBP75Ms   *float64 `json:"ttfb_p75_ms"`
	DCLP75Ms    *float64 `json:"dcl_p75_ms"`
	LoadP75Ms   *float64 `json:"load_p75_ms"`
	ErrorRate   float64  `json:"error_rate"`
	JSPerNav    float64  `json:"js_errors_per_navigation"`
	Navigations int64    `json:"navigations"`
	Requests    int64    `json:"requests"`
	Nav4xx      int64    `json:"nav_4xx"`
	Nav5xx      int64    `json:"nav_5xx"`
	NavFailed   int64    `json:"nav_failed"`
	Req4xx      int64    `json:"req_4xx"`
	Req5xx      int64    `json:"req_5xx"`
	ReqFailed   int64    `json:"req_failed"`
	JSErrors    int64    `json:"js_errors"`
}

// ramp is 1 at or below good, 0 at or above poor, linear between.
func ramp(v, good, poor float64) float64 {
	switch {
	case v <= good:
		return 1
	case v >= poor:
		return 0
	}
	return (poor - v) / (poor - good)
}

// Compute scores t; see the formula at the top of this file.
func Compute(t Totals) Result {
	r := Result{Band: "no_data", Navigations: t.Navigations, Requests: t.Requests,
		Nav4xx: t.Nav4xx, Nav5xx: t.Nav5xx, NavFailed: t.NavFailed,
		Req4xx: t.Req4xx, Req5xx: t.Req5xx, ReqFailed: t.ReqFailed, JSErrors: t.JSErrors}
	p75 := func(h []int64) *float64 {
		if v, ok := Percentile(h, 0.75); ok {
			v = math.Round(v)
			return &v
		}
		return nil
	}
	r.TTFBP75Ms, r.DCLP75Ms, r.LoadP75Ms = p75(t.TTFBHist), p75(t.DCLHist), p75(t.LoadHist)
	if denom := t.Navigations + t.NavFailed + t.Requests; denom > 0 {
		r.ErrorRate = float64(t.Nav5xx+t.NavFailed+t.Req5xx+t.ReqFailed) / float64(denom)
		if r.ErrorRate > 1 {
			r.ErrorRate = 1
		}
	}
	if t.Navigations > 0 {
		r.JSPerNav = float64(t.JSErrors) / float64(t.Navigations)
	}
	if t.Navigations < MinNavigations {
		return r
	}
	// A load whose timing never arrived (the histogram is empty) is not
	// scored as fast: the component counts as neither good nor poor.
	ttfb, load := 0.5, 0.5
	if r.TTFBP75Ms != nil {
		ttfb = ramp(*r.TTFBP75Ms, TTFBGoodMs, TTFBPoorMs)
	}
	if r.LoadP75Ms != nil {
		load = ramp(*r.LoadP75Ms, LoadGoodMs, LoadPoorMs)
	}
	v := weightTTFB*ttfb + weightLoad*load +
		weightErrors*ramp(r.ErrorRate, ErrorRateGood, ErrorRatePoor) +
		weightJSErrors*ramp(r.JSPerNav, JSPerNavGood, JSPerNavPoor)
	score := int(math.Round(100 * v))
	r.Score = &score
	r.Band = Band(score)
	return r
}

// Band names a score's range.
func Band(score int) string {
	switch {
	case score >= BandGoodAtLeast:
		return "good"
	case score >= BandFairAtLeast:
		return "fair"
	}
	return "poor"
}
