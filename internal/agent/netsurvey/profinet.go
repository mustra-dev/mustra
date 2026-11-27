package netsurvey

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Profinet DCP (Discovery and basic Configuration Protocol): one
// Identify-All request per attached network, on layer 2.
//
// Why this is safe: Identify asks every Profinet device on the segment to
// report its station name, vendor/device ID, role and IP settings. DCP's
// Set service (which renames a station, changes its IP or flashes its
// LED) and the factory-reset Set are never built here: dcpIdentifyAll is
// the only frame this package writes. Identify is what engineering tools
// send when their project view opens.
//
// It is a multicast to the whole layer 2 segment, so it is sent only on
// an interface whose network a job names exactly, and answers are kept
// only when the device's IP is in scope (or it has none yet).

const (
	dcpEtherType       = 0x8892
	dcpFrameIdentify   = 0xFEFE
	dcpFrameIdentifyOK = 0xFEFF
	dcpServiceIdentify = 0x05
)

// dcpMulticast is the Profinet DCP Identify multicast address.
var dcpMulticast = net.HardwareAddr{0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}

// dcpIdentifyAll builds the Ethernet frame for an Identify-All request.
func dcpIdentifyAll(src net.HardwareAddr, xid uint32) []byte {
	b := make([]byte, 60) // minimum Ethernet frame, zero padded
	copy(b[0:6], dcpMulticast)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:], dcpEtherType)
	binary.BigEndian.PutUint16(b[14:], dcpFrameIdentify)
	b[16] = dcpServiceIdentify
	b[17] = 0x00 // request
	binary.BigEndian.PutUint32(b[18:], xid)
	binary.BigEndian.PutUint16(b[22:], 0x0001) // response delay factor: spread over 10 ms slots
	binary.BigEndian.PutUint16(b[24:], 4)      // DCP data length
	b[26], b[27] = 0xFF, 0xFF                  // option All, suboption All
	binary.BigEndian.PutUint16(b[28:], 0)      // block length
	return b
}

// dcpDevice is a parsed Identify response.
type dcpDevice struct {
	MAC         net.HardwareAddr
	IP          netip.Addr
	StationName string
	VendorText  string
	VendorID    int
	DeviceID    int
	Role        string
}

// parseDCPIdentify decodes an Ethernet frame answering xid.
func parseDCPIdentify(frame []byte, xid uint32) (dcpDevice, error) {
	var d dcpDevice
	if len(frame) < 26 {
		return d, fmt.Errorf("dcp: short frame")
	}
	off := 12
	if binary.BigEndian.Uint16(frame[off:]) == 0x8100 { // 802.1Q tag
		off += 4
	}
	if len(frame) < off+14 || binary.BigEndian.Uint16(frame[off:]) != dcpEtherType {
		return d, fmt.Errorf("dcp: not a Profinet frame")
	}
	p := frame[off+2:]
	if binary.BigEndian.Uint16(p) != dcpFrameIdentifyOK || p[2] != dcpServiceIdentify || p[3] != 0x01 {
		return d, fmt.Errorf("dcp: not an Identify response")
	}
	if binary.BigEndian.Uint32(p[4:]) != xid {
		return d, fmt.Errorf("dcp: another request's answer")
	}
	l := int(binary.BigEndian.Uint16(p[10:]))
	blocks := p[12:]
	if l > len(blocks) {
		return d, fmt.Errorf("dcp: truncated")
	}
	blocks = blocks[:l]
	d.MAC = append(net.HardwareAddr{}, frame[6:12]...)
	for len(blocks) >= 4 {
		opt, sub := blocks[0], blocks[1]
		bl := int(binary.BigEndian.Uint16(blocks[2:]))
		if len(blocks) < 4+bl {
			return d, fmt.Errorf("dcp: truncated block")
		}
		body := blocks[4 : 4+bl]
		next := 4 + bl
		if bl%2 == 1 && len(blocks) > next {
			next++ // blocks are padded to an even length
		}
		blocks = blocks[next:]
		if len(body) < 2 {
			continue
		}
		data := body[2:] // after BlockInfo
		switch {
		case opt == 0x01 && sub == 0x02 && len(data) >= 4:
			d.IP = netip.AddrFrom4([4]byte{data[0], data[1], data[2], data[3]})
		case opt == 0x02 && sub == 0x01:
			d.VendorText = cleanString(string(data))
		case opt == 0x02 && sub == 0x02:
			d.StationName = cleanString(string(data))
		case opt == 0x02 && sub == 0x03 && len(data) >= 4:
			d.VendorID = int(binary.BigEndian.Uint16(data))
			d.DeviceID = int(binary.BigEndian.Uint16(data[2:]))
		case opt == 0x02 && sub == 0x04 && len(data) >= 1:
			d.Role = dcpRole(data[0])
		}
	}
	return d, nil
}

func dcpRole(b byte) string {
	var roles []string
	if b&0x02 != 0 {
		roles = append(roles, "io-controller")
	}
	if b&0x01 != 0 {
		roles = append(roles, "io-device")
	}
	if b&0x04 != 0 {
		roles = append(roles, "io-multidevice")
	}
	if b&0x08 != 0 {
		roles = append(roles, "supervisor")
	}
	return strings.Join(roles, ",")
}

// device turns an Identify response into a survey device.
func (d dcpDevice) device() proto.NetSurveyDevice {
	out := proto.NetSurveyDevice{MAC: strings.ToLower(d.MAC.String()), Protocols: []string{proto.NetSurveyProfinet},
		Name: d.StationName, Model: d.VendorText, VendorID: d.VendorID, ProductCode: d.DeviceID,
		DeviceRole: d.Role, DeviceType: "Profinet device"}
	if d.IP.IsValid() && !d.IP.IsUnspecified() {
		out.IP = d.IP.String()
	}
	if d.VendorID == 0x002A {
		out.Vendor = "Siemens"
	} else if d.VendorID != 0 {
		out.Vendor = fmt.Sprintf("PI vendor 0x%04x", d.VendorID)
	}
	return out
}
