//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// On Linux the socket tables in /proc/net are cheap to read; what costs is
// finding each socket's process, which means reading the link behind every
// open file of every process. gopsutil did that on every poll, for every
// socket: about 40% of an idle agent's allocations and most of its idle CPU
// (#50). The recorder only needs the process of a socket it has not seen
// before, so this reads the tables every poll and walks /proc/*/fd only when
// a new socket appears, and only until it has found those.

func init() { listConnections = procConnections }

type procTable []connRow

func (t procTable) rows() []connRow { return t }

func procConnections(ctx context.Context) (connTable, error) {
	var t procTable
	read := 0
	for _, f := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			continue // no IPv6 on this host, for one
		}
		read++
		t = append(t, parseProcNet(raw, f.proto)...)
	}
	if read == 0 {
		return nil, os.ErrNotExist
	}
	return t, nil
}

var tcpStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "0A": "LISTEN"}

// parseProcNet reads one /proc/net/{tcp,udp}[6] table:
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
//	 0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 ...
func parseProcNet(raw []byte, proto string) []connRow {
	var out []connRow
	sc := bufio.NewScanner(bytes.NewReader(raw))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, ok1 := parseHexAddr(f[1])
		rip, rport, ok2 := parseHexAddr(f[2])
		if !ok1 || !ok2 || f[9] == "0" {
			continue // inode 0: a socket in TIME_WAIT, with no process behind it
		}
		status := "NONE"
		if proto == "tcp" {
			status = tcpStates[f[3]]
			if status == "" {
				status = "OTHER"
			}
		}
		out = append(out, connRow{Proto: proto, Status: status, LocalIP: lip, LocalPort: lport,
			RemoteIP: rip, RemotePort: rport, ID: proto + ":" + f[9]})
	}
	return out
}

// parseHexAddr reads "0100007F:0035" (IPv4) or 32 hex digits for IPv6. The
// kernel prints each 32-bit word of the address in host byte order, which is
// little-endian on every platform the agent ships for.
func parseHexAddr(s string) (string, uint32, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, false
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String(), uint32(p), true
}

// pidOf walks /proc/*/fd for the sockets asked about and stops once it has
// found them all.
func (t procTable) pidOf(ids map[string]bool) map[string]int32 {
	out := map[string]int32{}
	if len(ids) == 0 {
		return out
	}
	// The table's IDs are "<proto>:<inode>"; the links name the inode only.
	want := map[string][]string{}
	for id := range ids {
		_, inode, _ := strings.Cut(id, ":")
		want[inode] = append(want[inode], id)
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := link[len("socket:[") : len(link)-1]
			for _, id := range want[inode] {
				if _, done := out[id]; !done {
					out[id] = int32(pid)
				}
			}
		}
		if len(out) == len(ids) {
			break
		}
	}
	return out
}
