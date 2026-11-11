//go:build linux

package agent

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	tcp := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1 0000000000000000 100 0 0 10 0
   1: 0505000A:C350 22D8B85D:01BB 01 00000000:00000000 02:000A7B1F 00000000  1000        0 34567 2 0000000000000000 20 4 30 10 -1
   2: 0505000A:C351 22D8B85D:01BB 06 00000000:00000000 03:00001234 00000000     0        0 0 3 0000000000000000
`)
	rows := parseProcNet(tcp, "tcp")
	if len(rows) != 2 {
		t.Fatalf("rows %+v (the TIME_WAIT socket with inode 0 must be skipped)", rows)
	}
	if r := rows[0]; r.Status != "LISTEN" || r.LocalIP != "127.0.0.1" || r.LocalPort != 53 || r.ID != "tcp:23456" {
		t.Errorf("listener %+v", r)
	}
	if r := rows[1]; r.Status != "ESTABLISHED" || r.LocalIP != "10.0.5.5" || r.RemoteIP != "93.184.216.34" || r.RemotePort != 443 {
		t.Errorf("outbound %+v", r)
	}
	tcp6 := []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1
   1: 0000000000000000FFFF00000505000A:C352 0000000000000000FFFF000022D8B85D:01BB 01 00000000:00000000 00:00000000 00000000     0        0 45679 1
`)
	rows = parseProcNet(tcp6, "tcp")
	if len(rows) != 2 || rows[0].LocalIP != "::1" || rows[0].LocalPort != 22 || rows[1].RemoteIP != "93.184.216.34" {
		t.Errorf("tcp6 %+v", rows)
	}
	udp := []byte(`   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 56789 2 0000000000000000 0
`)
	if rows = parseProcNet(udp, "udp"); len(rows) != 1 || rows[0].Status != "NONE" || rows[0].LocalPort != 68 {
		t.Errorf("udp %+v", rows)
	}
}

// Against the real /proc: a listener and a connection this process owns are
// in the table, and resolve to this process.
func TestProcConnectionsFindsOwnSockets(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	table, err := procConnections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range table.rows() {
		if (r.Status == "LISTEN" && r.LocalPort == port) || (r.Status == "ESTABLISHED" && r.RemotePort == port) {
			want[r.ID] = true
		}
	}
	if len(want) < 2 {
		t.Fatalf("found %d of the listener and the connection on port %d", len(want), port)
	}
	pids := table.pidOf(want)
	for id := range want {
		if pids[id] != int32(os.Getpid()) {
			t.Errorf("%s resolved to %d, want %d", id, pids[id], os.Getpid())
		}
	}
}
