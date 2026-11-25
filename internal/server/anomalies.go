package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mustra-dev/mustra/internal/anomaly"
	"github.com/mustra-dev/mustra/internal/store"
)

// Anomaly detection: each endpoint judged against its own normal, from
// data agents already send (the performance, processes and services
// sensors and the boot time in facts). Nothing new is collected on the
// endpoint and nothing leaves the server. The judging is
// internal/anomaly; this is the loop that feeds it.

const (
	anomalyEvery = 5 * time.Minute
	// anomalyBucket is the sampling resolution. The performance sensor
	// reports every minute; one value per five minutes is plenty for an
	// hourly median and a fifth of the rows.
	anomalyBucket = 5 * time.Minute
	// How far back each pass reads: twice the interval, so a pass that
	// ran late still sees every snapshot.
	anomalyLookback = 2 * anomalyEvery
	// anomalyDetectWindow is how much recent history detection reads per
	// endpoint: enough for the trailing median plus the sustained run.
	anomalyDetectWindow = anomaly.StatWindow + anomaly.Sustain + time.Hour
	// anomalyBaselineEvery: baselines are medians over two weeks, so an
	// hour-old one is as good as a fresh one.
	anomalyBaselineEvery = time.Hour
	// anomalyChangeWindow is how long before an anomaly a change counts
	// as "shortly before".
	anomalyChangeWindow = 24 * time.Hour
)

// anomalyRetention is how long each tier is kept (see schema.sql).
var anomalyRetention = store.AnomalyRetention{
	Samples:             26 * time.Hour,
	Hours:               anomaly.BaselineWindow + 24*time.Hour,
	Boots:               30 * 24 * time.Hour,
	Closed:              90 * 24 * time.Hour,
	ExpiredSuppressions: 30 * 24 * time.Hour,
}

// anomalyLoop samples, rolls up, recomputes baselines hourly, detects and
// prunes, every five minutes until ctx ends.
func (s *Server) anomalyLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	ticker := time.NewTicker(anomalyEvery)
	defer ticker.Stop()
	var lastBaseline time.Time
	for {
		now := time.Now()
		if err := s.runAnomalyPass(ctx, now, now.Sub(lastBaseline) >= anomalyBaselineEvery); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("anomaly detection pass failed", "error", err)
		} else if now.Sub(lastBaseline) >= anomalyBaselineEvery {
			lastBaseline = now
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runAnomalyPass is one pass of the loop. Split out so a test can drive
// it with a clock of its own.
func (s *Server) runAnomalyPass(ctx context.Context, now time.Time, baselines bool) error {
	if err := s.sampleAnomalyMetrics(ctx, now); err != nil {
		return err
	}
	if err := s.store.RollUpAnomalyHours(ctx, now.Add(-3*time.Hour), now); err != nil {
		return err
	}
	if baselines {
		if err := s.store.RecomputeAnomalyBaselines(ctx, now.Add(-anomaly.BaselineWindow), now); err != nil {
			return err
		}
	}
	if err := s.detectAnomalies(ctx, now); err != nil {
		return err
	}
	return s.store.PruneAnomalyData(ctx, now, anomalyRetention)
}

// sampleAnomalyMetrics stores the values every snapshot collected since
// the last pass carries.
func (s *Server) sampleAnomalyMetrics(ctx context.Context, now time.Time) error {
	since := now.Add(-anomalyLookback)
	perf, err := s.store.RecentPerformance(ctx, since)
	if err != nil {
		return err
	}
	var samples []store.AnomalySample
	for _, p := range perf {
		var v struct {
			CPU     *float64 `json:"cpu_current"`
			Memory  *float64 `json:"memory_current"`
			Disk    *float64 `json:"disk_current"`
			Samples int      `json:"samples"`
		}
		// One endpoint's malformed summary costs it this sample, nothing
		// more.
		if json.Unmarshal(p.Data, &v) != nil || v.Samples == 0 || p.CollectedAt.After(now.Add(5*time.Minute)) {
			continue
		}
		at := p.CollectedAt.Truncate(anomalyBucket)
		for key, val := range map[string]*float64{"cpu": v.CPU, "memory": v.Memory, "disk": v.Disk} {
			m, _ := anomaly.Lookup(key)
			if val == nil {
				continue
			}
			if clean, ok := m.Clean(*val); ok {
				samples = append(samples, store.AnomalySample{AgentID: p.AgentID, Metric: key, At: at, Value: clean})
			}
		}
	}
	if err := s.store.InsertAnomalySamples(ctx, samples); err != nil {
		return err
	}
	if err := s.store.SampleInventoryMetrics(ctx, since, anomalyBucket); err != nil {
		return err
	}
	return s.store.SampleReboots(ctx, now.Truncate(anomalyBucket))
}

type anomalyKey struct{ agent, metric string }

// detectAnomalies judges every endpoint and metric with recent samples or
// an open anomaly, and records what changed.
func (s *Server) detectAnomalies(ctx context.Context, now time.Time) error {
	baselines, err := s.store.ListAnomalyBaselines(ctx, "")
	if err != nil {
		return err
	}
	base := map[anomalyKey]anomaly.Baseline{}
	for _, b := range baselines {
		base[anomalyKey{b.AgentID, b.Metric}] = anomaly.Baseline{Median: b.Median, MAD: b.MAD, Hours: b.Hours}
	}
	rows, err := s.store.ListAnomalySamples(ctx, now.Add(-anomalyDetectWindow), "", "")
	if err != nil {
		return err
	}
	series := map[anomalyKey][]anomaly.Sample{}
	for _, r := range rows {
		k := anomalyKey{r.AgentID, r.Metric}
		series[k] = append(series[k], anomaly.Sample{At: r.At, Value: r.Value})
	}
	open, err := s.store.ListAnomalies(ctx, store.AnomalyFilter{State: "open"})
	if err != nil {
		return err
	}
	opened := map[anomalyKey]store.Anomaly{}
	for _, a := range open {
		opened[anomalyKey{a.AgentID, a.Metric}] = a
	}
	keys := map[anomalyKey]bool{}
	for k := range series {
		keys[k] = true
	}
	for k := range opened {
		keys[k] = true
	}
	for k := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m, ok := anomaly.Lookup(k.metric)
		if !ok {
			continue
		}
		var st *anomaly.Open
		cur, isOpen := opened[k]
		if isOpen {
			st = &anomaly.Open{Direction: cur.Direction, StartedAt: cur.StartedAt, PeakValue: cur.PeakValue, PeakZ: cur.PeakZ}
		}
		b := base[k]
		if isOpen && !b.Ready() {
			// Judge an open anomaly against the baseline it opened on if
			// the stored one has gone (pruned with the endpoint's hours).
			b = anomaly.Baseline{Median: cur.BaselineMedian, MAD: cur.BaselineMAD, Hours: anomaly.MinBaselineHours}
		}
		d := anomaly.Evaluate(m, b, series[k], st, now)
		switch d.Action {
		case anomaly.Start:
			// Detection reads only the last few hours, which is enough to
			// decide but not to say when a long run began. Opening is
			// rare, so read the endpoint's whole retained day for that.
			if day, err := s.store.ListAnomalySamples(ctx, now.Add(-anomalyRetention.Samples), k.agent, k.metric); err == nil {
				var full []anomaly.Sample
				for _, r := range day {
					full = append(full, anomaly.Sample{At: r.At, Value: r.Value})
				}
				if again := anomaly.Evaluate(m, b, full, nil, now); again.Action == anomaly.Start && again.Direction == d.Direction {
					d = again
				}
			}
			level, score := anomaly.Severity(d.PeakZ, now.Sub(d.At))
			change, changeAt, err := s.store.RecentChange(ctx, k.agent, d.At.Add(-anomalyChangeWindow), d.At)
			if err != nil {
				s.logger.Warn("anomaly change lookup failed", "agent", k.agent, "error", err)
			}
			if _, err := s.store.OpenAnomaly(ctx, store.Anomaly{
				ID: newID("anom-"), AgentID: k.agent, Metric: k.metric, Direction: d.Direction,
				StartedAt: d.At, LastSeenAt: now, BaselineMedian: b.Median, BaselineMAD: b.MAD,
				Value: d.Value, PeakValue: d.PeakValue, PeakZ: d.PeakZ, Severity: level, Score: score,
				Change: change, ChangeAt: changeAt,
			}); err != nil {
				return err
			}
		case anomaly.Update:
			level, score := anomaly.Severity(d.PeakZ, now.Sub(cur.StartedAt))
			if err := s.store.UpdateAnomaly(ctx, cur.ID, now, d.Value, d.PeakValue, d.PeakZ, level, score); err != nil {
				return err
			}
		case anomaly.Close:
			if err := s.store.CloseAnomaly(ctx, cur.ID, d.At, d.NoData); err != nil {
				return err
			}
		}
	}
	return nil
}
