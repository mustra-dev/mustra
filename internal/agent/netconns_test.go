package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// fakeTable stands in for the socket table and counts what it was asked.
type fakeTable struct {
	rs    []connRow
	asked *[]map[string]bool
}

func (t fakeTable) rows() []connRow { return t.rs }
func (t fakeTable) pidOf(ids map[string]bool) map[string]int32 {
	*t.asked = append(*t.asked, ids)
	out := map[string]int32{}
	for id := range ids {
		out[id] = 4242
	}
	return out
}

// The diff reports a flow once, however many polls it lasts, and looks up a
// process only for sockets it has not seen before.
func TestNetworkLoopResolvesOnlyNewSockets(t *testing.T) {
	listen := connRow{Proto: "tcp", Status: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 22, ID: "tcp:100"}
	out := connRow{Proto: "tcp", Status: "ESTABLISHED", LocalIP: "10.0.0.5", LocalPort: 50000, RemoteIP: "93.184.216.34", RemotePort: 443, ID: "tcp:200"}
	loop := connRow{Proto: "tcp", Status: "ESTABLISHED", LocalIP: "127.0.0.1", LocalPort: 5000, RemoteIP: "127.0.0.1", RemotePort: 6000, ID: "tcp:300"}
	polls := [][]connRow{
		{listen},            // the first poll is the baseline: nothing reported
		{listen, out, loop}, // a new outbound flow; loopback is never reported
		{listen, out, loop}, // nothing new
	}
	var asked []map[string]bool
	i := 0
	old := listConnections
	t.Cleanup(func() { listConnections = old })
	ctx, cancel := context.WithCancel(context.Background())
	listConnections = func(context.Context) (connTable, error) {
		if i >= len(polls) {
			cancel()
			return fakeTable{asked: &asked}, nil
		}
		i++
		return fakeTable{rs: polls[i-1], asked: &asked}, nil
	}
	r := &recorder{events: make(chan proto.RecorderEvent, 10), pending: map[string]*proto.RecorderEvent{}}
	done := make(chan struct{})
	go func() { r.networkLoop(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(4 * recorderPollInterval):
		t.Fatal("the loop did not finish")
	}
	close(r.events)
	var got []proto.RecorderEvent
	for ev := range r.events {
		got = append(got, ev)
	}
	if len(got) != 1 || got[0].Op != "connect" || got[0].RemoteIP != "93.184.216.34" || got[0].PID != 4242 {
		t.Fatalf("events %+v", got)
	}
	if len(asked) != 1 || len(asked[0]) != 1 || !asked[0]["tcp:200"] {
		t.Errorf("asked for processes of %v, want only the new socket once", asked)
	}
}
