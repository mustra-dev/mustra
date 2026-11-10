package server

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// A restore terminates every connection to the database, the pool's own
// included; the audit row written right after it must still land (#41).
func TestAuditSurvivesTerminatedConnections(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}

	// Warm the pool, then kill every other backend, as pg_restore's
	// connection reset does.
	s.audit(ctx, auditEvent{Action: "test.warm", Actor: "t"})
	killer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer killer.Close(ctx)
	if _, err := killer.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`); err != nil {
		t.Fatal(err)
	}

	target := idgen.New("restore-")
	s.audit(ctx, auditEvent{Action: "backup.restore", Actor: "t", Target: target, Severity: "critical"})
	events, err := st.ListAuditEvents(ctx, "backup.restore", "t", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Target == target {
			return
		}
	}
	t.Error("the audit row after terminated connections was lost")
}
