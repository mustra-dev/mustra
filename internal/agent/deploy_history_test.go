package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func historyAgent(t *testing.T) *Agent {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	lastHistoryPrune.Clear()
	return &Agent{store: st, logger: slog.New(slog.DiscardHandler)}
}

// seed writes contiguous batches straight into the bucket, ending at end.
func seed(t *testing.T, a *Agent, kind string, n int, step time.Duration, end time.Time, rows func(i int) []map[string]any) {
	t.Helper()
	err := a.store.db.Update(func(tx *bolt.Tx) error {
		root, _ := tx.CreateBucketIfNotExists(deployHistoryBucket)
		b, _ := root.CreateBucketIfNotExists([]byte(kind))
		for i := 0; i < n; i++ {
			until := end.Add(-time.Duration(n-1-i) * step)
			raw, _ := json.Marshal(deployHistoryBatch{Since: until.Add(-step), Until: until, Complete: true, Rows: rows(i)})
			if err := b.Put([]byte(until.UTC().Format(time.RFC3339Nano)), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, a *Agent, kind string) (n int, oldest time.Time) {
	t.Helper()
	a.store.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(deployHistoryBucket).Bucket([]byte(kind))
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if n == 0 {
				oldest, _ = time.Parse(time.RFC3339Nano, string(k))
			}
			n++
		}
		return nil
	})
	return n, oldest
}

func TestPruneDeployHistoryByAge(t *testing.T) {
	a := historyAgent(t)
	now := time.Now().UTC()
	// 500 hourly batches: the newest 25 are within 24 hours (0..24h old).
	seed(t, a, "process_events", 500, time.Hour, now, func(int) []map[string]any { return nil })
	if err := pruneDeployHistory(a.store.db, "process_events", now); err != nil {
		t.Fatal(err)
	}
	n, oldest := count(t, a, "process_events")
	if n != 25 || now.Sub(oldest) > deployHistoryKeep {
		t.Errorf("kept %d, oldest %v old", n, now.Sub(oldest))
	}
}

func TestPruneDeployHistoryBySize(t *testing.T) {
	a := historyAgent(t)
	now := time.Now().UTC()
	big := strings.Repeat("x", 100_000)
	// 500 recent batches of ~100 KB: about 50 MB, over the 16 MB budget.
	seed(t, a, "file_events", 500, time.Second, now, func(int) []map[string]any { return []map[string]any{{"blob": big}} })
	if err := pruneDeployHistory(a.store.db, "file_events", now); err != nil {
		t.Fatal(err)
	}
	n, _ := count(t, a, "file_events")
	if n < 100 || n > 170 {
		t.Errorf("kept %d batches of ~100 KB under a 16 MB budget", n)
	}
	// The newest survive, the oldest go.
	var newest string
	a.store.db.View(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(deployHistoryBucket).Bucket([]byte("file_events")).Cursor().Last()
		newest = string(k)
		return nil
	})
	if newest != now.Format(time.RFC3339Nano) {
		t.Errorf("newest kept is %s", newest)
	}
}

func TestPruneDropsKeysItDidNotWrite(t *testing.T) {
	a := historyAgent(t)
	now := time.Now().UTC()
	seed(t, a, "process_events", 10, time.Minute, now, func(int) []map[string]any { return nil })
	a.store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(deployHistoryBucket).Bucket([]byte("process_events")).Put([]byte("zzz-not-a-time"), []byte("{}"))
	})
	pruneDeployHistory(a.store.db, "process_events", now)
	if n, _ := count(t, a, "process_events"); n != 10 {
		t.Errorf("kept %d, want the 10 real batches", n)
	}
}

// The scan goes on past the first batch: returning nil from a bbolt ForEach
// callback moves to the next key. A long lookback over many batches works.
func TestDeployHistoryLongLookbackSpansBatches(t *testing.T) {
	a := historyAgent(t)
	now := time.Now().UTC()
	at := func(i int) string { return now.Add(-time.Duration(3600-i*60) * time.Second).Format(time.RFC3339Nano) }
	seed(t, a, "process_events", 60, time.Minute, now, func(i int) []map[string]any {
		return []map[string]any{{"name": "batch", "at": at(i)}}
	})
	rows, err := a.deployHistoryRows("process_events", 3600, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 59 {
		t.Errorf("an hour's lookback over 60 batches found %d rows", len(rows))
	}
}

func TestDeployHistoryGapAndStaleness(t *testing.T) {
	a := historyAgent(t)
	now := time.Now().UTC()
	// Coverage that ends two minutes ago is not current.
	seed(t, a, "process_events", 10, time.Minute, now.Add(-2*time.Minute), func(int) []map[string]any { return nil })
	if _, err := a.deployHistoryRows("process_events", 300, ""); err == nil || !strings.Contains(err.Error(), "not current") {
		t.Errorf("stale history: %v", err)
	}
}

// A quiet watcher records one marker a minute, spanning the quiet period, and
// a check that asks gets coverage up to now.
func TestQuietProcessWatcherMarksOnceAMinuteAndOnRequest(t *testing.T) {
	a := historyAgent(t)
	a.historyFlush = map[string]chan chan struct{}{"process_events": make(chan chan struct{})}
	start := time.Now().UTC().Add(-30 * time.Second)
	pw := &procWatcher{agent: a, source: "netlink", since: start}
	for range 12 { // a minute of 5-second ticks, all quiet
		pw.flush(context.Background(), false)
	}
	if n, _ := count0(a, "process_events"); n != 0 {
		t.Fatalf("a quiet half minute wrote %d markers", n)
	}
	pw.since = time.Now().UTC().Add(-quietMarkerEvery - time.Second)
	pw.flush(context.Background(), false)
	if n, _ := count0(a, "process_events"); n != 1 {
		t.Fatalf("a quiet minute wrote %d markers, want 1", n)
	}

	// A check asks the running watcher for coverage up to now.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case done := <-a.historyFlush["process_events"]:
				pw.flush(ctx, true)
				close(done)
			}
		}
	}()
	if _, err := a.deployHistoryRows("process_events", 60, ""); err != nil {
		t.Errorf("a check after a forced flush: %v", err)
	}
}

func count0(a *Agent, kind string) (int, error) {
	n := 0
	err := a.store.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(deployHistoryBucket)
		if root == nil {
			return nil
		}
		b := root.Bucket([]byte(kind))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error { n++; return nil })
	})
	return n, err
}
