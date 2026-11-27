//go:build linux

package netsurvey

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// profinetIdentify sends one DCP Identify-All on the named interface and
// collects the answers until wait has passed. It needs a raw AF_PACKET
// socket, so CAP_NET_RAW: the agent's service has it as root.
func profinetIdentify(ctx context.Context, lim *Limiter, ifname string, wait time.Duration) ([]dcpDevice, error) {
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	if len(ifc.HardwareAddr) != 6 {
		return nil, fmt.Errorf("%s has no Ethernet address", ifname)
	}
	proto := htons(dcpEtherType)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)
	ll := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifc.Index}
	if err := unix.Bind(fd, ll); err != nil {
		return nil, fmt.Errorf("bind %s: %w", ifname, err)
	}
	// Short receive timeouts so the loop notices the deadline and ctx.
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	var x [4]byte
	_, _ = rand.Read(x[:])
	xid := binary.BigEndian.Uint32(x[:])
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	dst := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifc.Index, Halen: 6}
	copy(dst.Addr[:], dcpMulticast)
	if err := unix.Sendto(fd, dcpIdentifyAll(ifc.HardwareAddr, xid), 0, dst); err != nil {
		return nil, fmt.Errorf("send on %s: %w", ifname, err)
	}
	deadline := time.Now().Add(wait)
	buf := make([]byte, 1600)
	seen := map[string]bool{}
	var out []dcpDevice
	for time.Now().Before(deadline) && ctx.Err() == nil && len(out) < 1024 {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // EAGAIN on the receive timeout
		}
		d, err := parseDCPIdentify(buf[:n], xid)
		if err != nil || seen[d.MAC.String()] {
			continue
		}
		seen[d.MAC.String()] = true
		out = append(out, d)
	}
	return out, ctx.Err()
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

const profinetSupported = ""
