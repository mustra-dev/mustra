package agent

import (
	"context"

	gnet "github.com/shirou/gopsutil/v4/net"
)

// connRow is one socket for the recorder's network diff. ID tells sockets
// apart across polls: the socket inode where the platform has one, so the
// owning process need only be found for sockets not seen before.
type connRow struct {
	Proto, Status string // "tcp"/"udp"; "LISTEN", "ESTABLISHED", "SYN_SENT", or other
	LocalIP       string
	LocalPort     uint32
	RemoteIP      string
	RemotePort    uint32
	ID            string
	PID           int32
}

// connTable lists sockets; pidOf finds the process behind those it is asked
// about, at whatever cost the platform needs, and only when asked.
type connTable interface {
	rows() []connRow
	pidOf(ids map[string]bool) map[string]int32
}

// listConnections is the platform's socket table: /proc on Linux, gopsutil
// elsewhere.
var listConnections = gopsutilConnections

type gopsutilTable []connRow

func (t gopsutilTable) rows() []connRow { return t }
func (t gopsutilTable) pidOf(ids map[string]bool) map[string]int32 {
	out := map[string]int32{}
	for _, r := range t {
		if ids[r.ID] {
			out[r.ID] = r.PID
		}
	}
	return out
}

func gopsutilConnections(ctx context.Context) (connTable, error) {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}
	t := make(gopsutilTable, 0, len(conns))
	for _, c := range conns {
		p := "tcp"
		if c.Type == 2 { // SOCK_DGRAM
			p = "udp"
		}
		t = append(t, connRow{Proto: p, Status: c.Status, LocalIP: c.Laddr.IP, LocalPort: c.Laddr.Port,
			RemoteIP: c.Raddr.IP, RemotePort: c.Raddr.Port, PID: c.Pid,
			ID: p + "|" + c.Laddr.IP + "|" + c.Raddr.IP + "|" + itoa(c.Laddr.Port) + "|" + itoa(c.Raddr.Port) + "|" + itoa(uint32(c.Pid))})
	}
	return t, nil
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
