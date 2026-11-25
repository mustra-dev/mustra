package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
)

func saasStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	agent := idgen.New("agt-")
	if err := s.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "saas-" + agent, OS: "linux", Arch: "amd64", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(context.Background(), agent) })
	return s, agent
}

func saasTestApp(t *testing.T, s *Store) string {
	t.Helper()
	id := "it-" + idgen.New("")[:12]
	if _, err := s.CreateSaaSApp(context.Background(), SaaSApp{ID: id, Name: "Integration " + id, Domains: []string{id + ".example"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteSaaSApp(context.Background(), id) })
	return id
}

func saasAgg(app string, at time.Time, navs, bucket int) proto.SaaSAggregate {
	h := make([]int, proto.SaaSHistogramLen)
	h[bucket] = navs
	return proto.SaaSAggregate{App: app, Browser: "chrome", WindowStart: at, WindowSeconds: 300, Navigations: navs,
		TTFBHist: h, DCLHist: h, LoadHist: h, Requests: navs * 10, Req5xx: 1, JSErrors: 2}
}

func TestSaaSBatchesAreIdempotentAndAdditive(t *testing.T) {
	s, agent := saasStore(t)
	ctx := context.Background()
	app := saasTestApp(t, s)
	w := time.Now().UTC().Truncate(5 * time.Minute).Add(-time.Hour)

	if ok, err := s.RecordSaaSBatch(ctx, agent, "batch-one-"+app, "1.0.0", []proto.SaaSAggregate{saasAgg(app, w, 10, 2)}); err != nil || !ok {
		t.Fatalf("first batch: %v %v", ok, err)
	}
	// The same batch again (a redelivery): no change.
	if ok, err := s.RecordSaaSBatch(ctx, agent, "batch-one-"+app, "1.0.0", []proto.SaaSAggregate{saasAgg(app, w, 10, 2)}); err != nil || ok {
		t.Fatalf("redelivery applied: %v %v", ok, err)
	}
	// Another batch for the same window adds, bucket by bucket.
	if _, err := s.RecordSaaSBatch(ctx, agent, "batch-two-"+app, "1.0.1", []proto.SaaSAggregate{saasAgg(app, w, 5, 9)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SaaSRollup(ctx, SaaSRollupQuery{Since: w.Add(-time.Hour), Until: w.Add(time.Hour), AppID: app, GroupBy: SaaSByAgent})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Key != agent || rows[0].Endpoints != 1 {
		t.Fatalf("rows %+v", rows)
	}
	tot := rows[0].Totals
	if tot.Navigations != 15 || tot.TTFBHist[2] != 10 || tot.TTFBHist[9] != 5 || tot.Requests != 150 || tot.Req5xx != 2 || tot.JSErrors != 4 {
		t.Fatalf("totals %+v", tot)
	}
	// Grouping by app and by time bucket sees the same numbers.
	byApp, _ := s.SaaSRollup(ctx, SaaSRollupQuery{Since: w.Add(-time.Hour), Until: w.Add(time.Hour), AppID: app, GroupBy: SaaSByApp})
	byBucket, _ := s.SaaSRollup(ctx, SaaSRollupQuery{Since: w.Add(-time.Hour), Until: w.Add(time.Hour), AppID: app, GroupBy: SaaSByBucket, BucketSeconds: 3600})
	if len(byApp) != 1 || byApp[0].Totals.Navigations != 15 || len(byBucket) != 1 || byBucket[0].Totals.Navigations != 15 {
		t.Fatalf("by app %+v, by bucket %+v", byApp, byBucket)
	}
	if want := w.Truncate(time.Hour); !byBucket[0].Bucket.Equal(want) {
		t.Fatalf("bucket %v, want %v", byBucket[0].Bucket, want)
	}
	if r := saasmon.Compute(tot); r.Score == nil {
		t.Fatal("15 loads should score")
	}
	eps, err := s.ListSaaSEndpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range eps {
		if e.AgentID == agent {
			found = e.ExtensionVersion == "1.0.1"
		}
	}
	if !found {
		t.Fatal("endpoint's extension version not recorded")
	}
}

func TestSaaSRetentionAndDelete(t *testing.T) {
	s, agent := saasStore(t)
	ctx := context.Background()
	app := saasTestApp(t, s)
	old := time.Now().UTC().Truncate(5*time.Minute).AddDate(0, 0, -40)
	recent := time.Now().UTC().Truncate(5 * time.Minute).Add(-10 * time.Minute)
	if _, err := s.RecordSaaSBatch(ctx, agent, "ret-"+app, "", []proto.SaaSAggregate{saasAgg(app, old, 3, 1), saasAgg(app, recent, 4, 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneSaaS(ctx, time.Now().AddDate(0, 0, -30)); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.SaaSRollup(ctx, SaaSRollupQuery{Since: old.Add(-time.Hour), Until: time.Now().Add(time.Hour), AppID: app, GroupBy: SaaSByApp})
	if len(rows) != 1 || rows[0].Totals.Navigations != 4 {
		t.Fatalf("after retention: %+v", rows)
	}
	// Deleting the app deletes what was measured of it.
	if err := s.DeleteSaaSApp(ctx, app); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM saas_samples WHERE app_id = $1`, app).Scan(&n); err != nil || n != 0 {
		t.Fatalf("samples left after delete: %d %v", n, err)
	}
	if err := s.DeleteSaaSApp(ctx, app); err != ErrSaaSAppNotFound {
		t.Fatalf("second delete: %v", err)
	}
}

// The default apps are seeded once: one the administrator deleted stays
// deleted when the schema is applied again on the next start.
func TestSaaSSeedRespectsDeletion(t *testing.T) {
	s, _ := saasStore(t)
	ctx := context.Background()
	apps, err := s.ListSaaSApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var zoom *SaaSApp
	for i := range apps {
		if apps[i].ID == "zoom" {
			zoom = &apps[i]
		}
	}
	if zoom == nil {
		t.Skip("the seeded zoom app was already removed from this database")
	}
	if !zoom.Builtin {
		t.Fatal("seeded app not marked builtin")
	}
	if err := s.DeleteSaaSApp(ctx, "zoom"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `INSERT INTO saas_apps (id, name, domains, builtin) VALUES ('zoom', 'Zoom', ARRAY['zoom.us'], true) ON CONFLICT DO NOTHING`)
	})
	again, err := Open(ctx, os.Getenv("MUSTRA_TEST_DEPLOY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, err := again.GetSaaSApp(ctx, "zoom"); err != ErrSaaSAppNotFound {
		t.Fatalf("deleted default app came back: %v", err)
	}
}
