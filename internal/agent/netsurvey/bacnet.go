package netsurvey

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// BACnet/IP: the unconfirmed Who-Is service, answered by I-Am.
//
// Why this is safe: Who-Is is how every BACnet workstation finds devices,
// and its only effect is that a device announces itself. It names no
// object and no property, so it cannot read a point, let alone write one,
// command an output or change a schedule. No confirmed service
// (ReadProperty, WriteProperty, DeviceCommunicationControl,
// ReinitializeDevice…) is ever built here.
//
// Who-Is is sent without a destination network, so BACnet routers do not
// forward it to other BACnet networks; an I-Am that arrives through a
// router (it carries a source network) is ignored, because its device is
// not at the address it came from. A broadcast Who-Is goes only to a
// subnet the job names that is exactly a network the endpoint is on.

const bacnetPort = 47808

// bacnetWhoIs builds a Who-Is without a device range: BVLC
// Original-Unicast-NPDU (0x0A) or Original-Broadcast-NPDU (0x0B), NPDU
// version 1 with no addressing, unconfirmed-request PDU, service 8.
func bacnetWhoIs(broadcast bool) []byte {
	fn := byte(0x0A)
	if broadcast {
		fn = 0x0B
	}
	return []byte{0x81, fn, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}
}

// bacnetIAm is a parsed I-Am.
type bacnetIAm struct {
	Instance     int
	MaxAPDU      int
	Segmentation int
	VendorID     int
}

var errBACnetNotIAm = errors.New("bacnet: not an I-Am")

// parseBACnetIAm decodes a BVLC frame carrying an I-Am. A frame that
// came through a BACnet router (NPDU source specifier) is refused.
func parseBACnetIAm(b []byte) (bacnetIAm, error) {
	var r bacnetIAm
	if len(b) < 4 || b[0] != 0x81 {
		return r, errBACnetNotIAm
	}
	if int(binary.BigEndian.Uint16(b[2:])) != len(b) {
		return r, fmt.Errorf("bacnet: BVLC length mismatch")
	}
	var npdu []byte
	switch b[1] {
	case 0x0A, 0x0B:
		npdu = b[4:]
	case 0x04: // Forwarded-NPDU: the original sender's B/IP address first
		if len(b) < 10 {
			return r, errBACnetNotIAm
		}
		npdu = b[10:]
	default:
		return r, errBACnetNotIAm
	}
	if len(npdu) < 2 || npdu[0] != 0x01 {
		return r, errBACnetNotIAm
	}
	ctl := npdu[1]
	if ctl&0x80 != 0 {
		return r, errBACnetNotIAm // a network-layer message
	}
	p := npdu[2:]
	hasDest := ctl&0x20 != 0
	if hasDest {
		if len(p) < 3 || len(p) < 3+int(p[2]) {
			return r, errBACnetNotIAm
		}
		p = p[3+int(p[2]):]
	}
	if ctl&0x08 != 0 {
		return r, fmt.Errorf("bacnet: routed I-Am")
	}
	if hasDest {
		if len(p) < 1 {
			return r, errBACnetNotIAm
		}
		p = p[1:] // hop count
	}
	if len(p) < 2 || p[0] != 0x10 || p[1] != 0x00 {
		return r, errBACnetNotIAm
	}
	p = p[2:]
	vals := make([]uint32, 0, 4)
	tags := make([]byte, 0, 4)
	for len(p) > 0 && len(vals) < 4 {
		tag := p[0]
		if tag&0x08 != 0 {
			return r, fmt.Errorf("bacnet: unexpected context tag")
		}
		l := int(tag & 0x07)
		p = p[1:]
		if l == 5 {
			if len(p) < 1 {
				return r, errBACnetNotIAm
			}
			l = int(p[0])
			p = p[1:]
		}
		if l > 4 || len(p) < l {
			return r, fmt.Errorf("bacnet: malformed I-Am value")
		}
		var v uint32
		for _, x := range p[:l] {
			v = v<<8 | uint32(x)
		}
		vals = append(vals, v)
		tags = append(tags, tag>>4)
		p = p[l:]
	}
	// object-identifier (tag 12), unsigned (2), enumerated (9), unsigned (2)
	if len(vals) != 4 || tags[0] != 12 || tags[1] != 2 || tags[2] != 9 || tags[3] != 2 {
		return r, fmt.Errorf("bacnet: malformed I-Am")
	}
	if objType := vals[0] >> 22; objType != 8 {
		return r, fmt.Errorf("bacnet: I-Am for a non-device object")
	}
	r.Instance = int(vals[0] & 0x3FFFFF)
	r.MaxAPDU = int(vals[1])
	r.Segmentation = int(vals[2])
	r.VendorID = int(vals[3])
	return r, nil
}

// bacnetVendors names the ASHRAE vendor IDs we are sure of.
var bacnetVendors = map[int]string{
	2: "Trane", 5: "Johnson Controls", 8: "Delta Controls", 17: "Honeywell",
	24: "Automated Logic", 260: "BACnet Stack (open source)",
}

// bacnetSession owns the one UDP socket a run uses for BACnet: unicast
// Who-Is go out from it and every I-Am is read from it. It binds 47808
// when that is free, since many devices answer Who-Is with a broadcast
// I-Am to that port; otherwise an ephemeral port still hears devices that
// answer the sender directly.
type bacnetSession struct {
	conn  *net.UDPConn
	plan  *Plan
	mu    sync.Mutex
	found map[netip.Addr]bacnetIAm
	done  chan struct{}
	errs  int
}

func newBACnetSession(plan *Plan) (*bacnetSession, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: bacnetPort})
	if err != nil {
		if conn, err = net.ListenUDP("udp4", &net.UDPAddr{}); err != nil {
			return nil, err
		}
	}
	s := &bacnetSession{conn: conn, plan: plan, found: map[netip.Addr]bacnetIAm{}, done: make(chan struct{})}
	go s.read()
	return s, nil
}

func (s *bacnetSession) read() {
	defer close(s.done)
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		src := from.Addr().Unmap()
		// Answers are held to the same scope as the probes.
		if !s.plan.InScope(src) {
			continue
		}
		iam, err := parseBACnetIAm(buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		if _, ok := s.found[src]; !ok {
			s.found[src] = iam
		}
		s.mu.Unlock()
	}
}

// whoIs sends one Who-Is to addr (a host, or a subnet's broadcast).
func (s *bacnetSession) whoIs(ctx context.Context, lim *Limiter, addr netip.Addr, broadcast bool) error {
	if err := lim.Wait(ctx); err != nil {
		return err
	}
	_, err := s.conn.WriteToUDPAddrPort(bacnetWhoIs(broadcast), netip.AddrPortFrom(addr, bacnetPort))
	if err != nil {
		s.mu.Lock()
		s.errs++
		s.mu.Unlock()
	}
	return nil
}

// finish waits for late answers, closes the socket and returns devices.
func (s *bacnetSession) finish(ctx context.Context, wait time.Duration) []proto.NetSurveyDevice {
	t := time.NewTimer(wait)
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	t.Stop()
	s.conn.Close()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]proto.NetSurveyDevice, 0, len(s.found))
	for addr, iam := range s.found {
		inst := iam.Instance
		d := proto.NetSurveyDevice{IP: addr.String(), Protocols: []string{proto.NetSurveyBACnet},
			VendorID: iam.VendorID, BACnetInstance: &inst, DeviceType: "BACnet device"}
		d.Vendor = bacnetVendors[iam.VendorID]
		if d.Vendor == "" {
			d.Vendor = fmt.Sprintf("BACnet vendor %d", iam.VendorID)
		}
		out = append(out, d)
	}
	return out
}
