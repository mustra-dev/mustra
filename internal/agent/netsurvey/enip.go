package netsurvey

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// EtherNet/IP: the encapsulation-layer ListIdentity command (0x0063), sent
// over UDP 44818 and, when that goes unanswered, over TCP 44818.
//
// Why this is safe: ListIdentity is answered by the encapsulation layer
// before any session exists. It carries no CIP service at all, so it
// cannot read or write a tag, change a mode or reach a connection; it is
// what commissioning tools broadcast to find devices. No RegisterSession
// or SendRRData (the commands that carry CIP requests) is ever built.

const (
	enipPort         = 44818
	enipListIdentity = 0x0063
	enipIdentityItem = 0x000C
)

func enipListIdentityRequest() []byte {
	b := make([]byte, 24) // header only: length 0, session 0, status 0, options 0
	binary.LittleEndian.PutUint16(b[0:], enipListIdentity)
	copy(b[12:20], "mustra\x00\x00") // sender context, echoed back
	return b
}

// enipIdentity is the CIP Identity item of a ListIdentity reply.
type enipIdentity struct {
	VendorID    int
	DeviceType  int
	ProductCode int
	Revision    string
	Serial      string
	ProductName string
	SocketAddr  netip.Addr
}

func parseENIPListIdentity(b []byte) (enipIdentity, error) {
	var id enipIdentity
	if len(b) < 24 {
		return id, fmt.Errorf("enip: short reply")
	}
	if binary.LittleEndian.Uint16(b[0:]) != enipListIdentity {
		return id, fmt.Errorf("enip: not a ListIdentity reply")
	}
	if status := binary.LittleEndian.Uint32(b[8:]); status != 0 {
		return id, fmt.Errorf("enip: status %d", status)
	}
	l := int(binary.LittleEndian.Uint16(b[2:]))
	if 24+l > len(b) {
		return id, fmt.Errorf("enip: truncated reply")
	}
	data := b[24 : 24+l]
	if len(data) < 2 {
		return id, fmt.Errorf("enip: no items")
	}
	count := int(binary.LittleEndian.Uint16(data))
	data = data[2:]
	for i := 0; i < count; i++ {
		if len(data) < 4 {
			return id, fmt.Errorf("enip: truncated item")
		}
		typ := binary.LittleEndian.Uint16(data)
		il := int(binary.LittleEndian.Uint16(data[2:]))
		if len(data) < 4+il {
			return id, fmt.Errorf("enip: truncated item")
		}
		item := data[4 : 4+il]
		data = data[4+il:]
		if typ != enipIdentityItem {
			continue
		}
		// version(2) sockaddr(16, big-endian) vendor(2) type(2) product(2)
		// revision(2) status(2) serial(4) name(1+n) state(1)
		if len(item) < 33 {
			return id, fmt.Errorf("enip: short identity item")
		}
		sa := item[2:18]
		id.SocketAddr = netip.AddrFrom4([4]byte{sa[4], sa[5], sa[6], sa[7]})
		p := item[18:]
		id.VendorID = int(binary.LittleEndian.Uint16(p[0:]))
		id.DeviceType = int(binary.LittleEndian.Uint16(p[2:]))
		id.ProductCode = int(binary.LittleEndian.Uint16(p[4:]))
		id.Revision = fmt.Sprintf("%d.%d", p[6], p[7])
		id.Serial = fmt.Sprintf("%08x", binary.LittleEndian.Uint32(p[10:]))
		nl := int(p[14])
		if len(p) < 15+nl {
			return id, fmt.Errorf("enip: truncated product name")
		}
		id.ProductName = cleanString(string(p[15 : 15+nl]))
		return id, nil
	}
	return id, fmt.Errorf("enip: no identity item")
}

// cipDeviceTypes names the CIP device profiles a survey is likely to meet.
var cipDeviceTypes = map[int]string{
	0x00: "generic device", 0x02: "AC drive", 0x07: "discrete I/O", 0x0C: "communications adapter",
	0x0E: "programmable logic controller", 0x13: "DC drive", 0x18: "human-machine interface",
	0x2B: "generic device", 0x2C: "managed switch",
}

// enipVendors names the ODVA vendor IDs we are sure of; others are shown
// by number.
var enipVendors = map[int]string{1: "Rockwell Automation/Allen-Bradley"}

func probeENIP(ctx context.Context, lim *Limiter, addr netip.Addr, timeout time.Duration) (*proto.NetSurveyDevice, error) {
	reply, err := enipUDP(ctx, lim, addr, timeout)
	if err != nil || reply == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		reply, err = enipTCP(ctx, lim, addr, timeout)
		if err != nil || reply == nil {
			return nil, err
		}
	}
	id, err := parseENIPListIdentity(reply)
	if err != nil {
		return nil, fmt.Errorf("enip %s: %w", addr, err)
	}
	dev := &proto.NetSurveyDevice{IP: addr.String(), Protocols: []string{proto.NetSurveyENIP},
		VendorID: id.VendorID, ProductCode: id.ProductCode, DeviceTypeCode: id.DeviceType,
		Model: id.ProductName, Firmware: id.Revision, Serial: id.Serial}
	dev.DeviceType = cipDeviceTypes[id.DeviceType]
	dev.Vendor = enipVendors[id.VendorID]
	if dev.Vendor == "" && id.VendorID != 0 {
		dev.Vendor = fmt.Sprintf("ODVA vendor %d", id.VendorID)
	}
	return dev, nil
}

func enipUDP(ctx context.Context, lim *Limiter, addr netip.Addr, timeout time.Duration) ([]byte, error) {
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, enipPort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.Write(enipListIdentityRequest()); err != nil {
		return nil, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil // silence, or ICMP port unreachable
	}
	return buf[:n], nil
}

func enipTCP(ctx context.Context, lim *Limiter, addr netip.Addr, timeout time.Duration) ([]byte, error) {
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, enipPort).String())
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(enipListIdentityRequest()); err != nil {
		return nil, nil
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, nil
	}
	l := int(binary.LittleEndian.Uint16(hdr[2:]))
	if l > 1024 {
		return nil, fmt.Errorf("enip %s: oversized reply", addr)
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil
	}
	return append(hdr, body...), nil
}
