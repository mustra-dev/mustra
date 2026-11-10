package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var deployHistoryBucket = []byte("deploy_sensor_history")

// The history used to cost a write transaction every 5 seconds per watcher,
// each walking and decoding the whole 24-hour bucket to prune it: 3-15% of a
// core and ~3 MB/min of writes on an idle host (#44). Quiet windows are now
// recorded once a minute, and pruning reads keys, stops at the first entry it
// keeps no more, and runs at most once a minute per source.
const (
	quietMarkerEvery    = time.Minute
	deployHistoryKeep   = 24 * time.Hour
	deployHistoryBudget = 16 << 20 // bytes of keys and values per source
	historyPruneEvery   = time.Minute
	historyFlushWait    = 2 * time.Second
)

var lastHistoryPrune sync.Map // kind -> time.Time

type deployHistoryBatch struct {
	Paths    []string         `json:"paths,omitempty"`
	Since    time.Time        `json:"since"`
	Until    time.Time        `json:"until"`
	Complete bool             `json:"complete"`
	Rows     []map[string]any `json:"rows"`
}

// A bounded local history preserves coverage, including empty observation
// windows. Missing windows and suppression invalidate negative assertions.
func (a *Agent) saveDeployHistory(kind string, since, until time.Time, data any, complete bool, paths ...[]string) {
	if a.store == nil {
		return
	}
	raw, e := json.Marshal(data)
	if e != nil {
		return
	}
	var rows []map[string]any
	if string(raw) != "null" {
		if json.Unmarshal(raw, &rows) != nil {
			return
		}
	}
	batch := deployHistoryBatch{Since: since, Until: until, Rows: rows, Complete: complete}
	if len(paths) > 0 {
		batch.Paths = paths[0]
	}
	raw, e = json.Marshal(batch)
	if e != nil {
		return
	}
	e = a.store.db.Update(func(tx *bolt.Tx) error {
		root, e := tx.CreateBucketIfNotExists(deployHistoryBucket)
		if e != nil {
			return e
		}
		b, e := root.CreateBucketIfNotExists([]byte(kind))
		if e != nil {
			return e
		}
		return b.Put([]byte(until.UTC().Format(time.RFC3339Nano)), raw)
	})
	if e != nil {
		a.logger.Warn("persist deployment sensor history", "sensor", kind, "error", e)
		return
	}
	if last, ok := lastHistoryPrune.Load(kind); !ok || time.Since(last.(time.Time)) >= historyPruneEvery {
		lastHistoryPrune.Store(kind, time.Now())
		if e := pruneDeployHistory(a.store.db, kind, time.Now()); e != nil {
			a.logger.Warn("prune deployment sensor history", "sensor", kind, "error", e)
		}
	}
}

// pruneDeployHistory keeps at most deployHistoryKeep and deployHistoryBudget
// per source. Keys are the batches' end times, so it walks newest first and
// reads only keys: once one entry is past the age or the running total, every
// older one is too, and it deletes the rest without decoding them.
func pruneDeployHistory(db *bolt.DB, kind string, now time.Time) error {
	return db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(deployHistoryBucket)
		if root == nil {
			return nil
		}
		b := root.Bucket([]byte(kind))
		if b == nil {
			return nil
		}
		var used int64
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			used += int64(len(k) + len(v))
			t, err := time.Parse(time.RFC3339Nano, string(k))
			if err == nil && used <= deployHistoryBudget && now.Sub(t) <= deployHistoryKeep {
				continue
			}
			if err != nil {
				// Not a key this code wrote; drop it alone.
				if e := c.Delete(); e != nil {
					return e
				}
				continue
			}
			for ; k != nil; k, _ = c.Prev() {
				if e := c.Delete(); e != nil {
					return e
				}
			}
			return nil
		}
		return nil
	})
}

// flushHistory asks the watcher for kind to record its current window, so a
// check reads history up to now rather than up to its last quiet marker. A
// watcher that is not running does not answer, and the coverage check then
// says the history is not current, as it should.
func (a *Agent) flushHistory(kind string) {
	ch := a.historyFlush[kind]
	if ch == nil {
		return
	}
	done := make(chan struct{})
	select {
	case ch <- done:
	case <-time.After(historyFlushWait):
		return
	}
	select {
	case <-done:
	case <-time.After(historyFlushWait):
	}
}
func (a *Agent) deployHistoryRows(kind string, lookback int, path string) ([]map[string]any, error) {
	if a.store == nil || lookback <= 0 || lookback > 86400 {
		return nil, fmt.Errorf("historical checks require a lookback from 1 to 86400 seconds")
	}
	a.flushHistory(kind)
	until := time.Now()
	since := until.Add(-time.Duration(lookback) * time.Second)
	covered := since
	rows := []map[string]any{}
	e := a.store.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(deployHistoryBucket)
		if root == nil {
			return fmt.Errorf("historical collection has no coverage")
		}
		b := root.Bucket([]byte(kind))
		if b == nil {
			return fmt.Errorf("historical sensor has no coverage")
		}
		return b.ForEach(func(k, v []byte) error {
			var entry deployHistoryBatch
			if e := json.Unmarshal(v, &entry); e != nil {
				return e
			}
			if entry.Until.Before(since) {
				return nil
			}
			if kind == "file_events" {
				if path == "" {
					return fmt.Errorf("file history requires an exact path filter to verify monitoring coverage")
				}
				dir := filepath.Dir(path)
				if canonical, e := filepath.EvalSymlinks(dir); e == nil {
					dir = canonical
				}
				coveredPath := false
				for _, p := range entry.Paths {
					canonical, e := filepath.EvalSymlinks(p)
					if e == nil && canonical == dir {
						coveredPath = true
					}
					if p == dir {
						coveredPath = true
					}
				}
				if !coveredPath {
					return fmt.Errorf("requested file was outside monitored directories during the window")
				}
			}
			if !entry.Complete {
				return fmt.Errorf("historical window contains suppression or incomplete monitoring")
			}
			if entry.Since.After(covered.Add(time.Second)) {
				return fmt.Errorf("historical window contains a collection gap")
			}
			covered = entry.Until
			for _, row := range entry.Rows {
				at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(row["at"]))
				if !at.IsZero() && (at.Before(since) || at.After(until)) {
					continue
				}
				rows = append(rows, row)
			}
			if len(rows) > 10000 {
				return fmt.Errorf("historical check exceeds 10000 rows")
			}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	if covered.Before(until.Add(-15 * time.Second)) {
		return nil, fmt.Errorf("historical collection is not current")
	}
	return rows, nil
}
