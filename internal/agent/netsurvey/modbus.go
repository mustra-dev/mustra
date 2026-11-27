package netsurvey

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Modbus TCP: function 43 (Encapsulated Interface Transport), MEI type 14
// (Read Device Identification), and nothing else.
//
// Why this is safe: function 43/14 only reads the device's identification
// objects (vendor, product code, revision, model). It is the one Modbus
// request with no access to coils, registers or files, so it cannot change
// a process value or an output. No other function code is ever built by
// this file; modbusRequest takes the object to read, not a function.
//
// Unit 255 is asked first: on Modbus TCP it addresses the server itself.
// Unit 0 is the fallback some devices answer on instead; through a serial
// gateway unit 0 is a broadcast, which slaves never reply to, and the
// request is still only a read.

const (
	modbusPort        = 502
	modbusFunction    = 0x2B
	modbusMEIDeviceID = 0x0E
	// Read Device ID codes: 1 basic stream, 2 regular stream.
	modbusReadBasic   = 0x01
	modbusReadRegular = 0x02
	// The most objects a device may make us page through.
	modbusMaxPages = 8
)

// modbusRequest builds the only Modbus frame this package sends.
func modbusRequest(txID uint16, unit, readCode, objectID byte) []byte {
	b := make([]byte, 11)
	binary.BigEndian.PutUint16(b[0:], txID)
	// Protocol identifier 0 (Modbus); length counts unit id + PDU.
	binary.BigEndian.PutUint16(b[4:], 5)
	b[6] = unit
	b[7] = modbusFunction
	b[8] = modbusMEIDeviceID
	b[9] = readCode
	b[10] = objectID
	return b
}

var errModbusException = errors.New("modbus exception")

// modbusDeviceIDPage is one parsed Read Device Identification response.
type modbusDeviceIDPage struct {
	Conformity byte
	More       bool
	NextObject byte
	Objects    map[byte]string
}

// parseModbusResponse decodes a full MBAP frame answering modbusRequest.
func parseModbusResponse(frame []byte, txID uint16, unit byte) (modbusDeviceIDPage, error) {
	var page modbusDeviceIDPage
	if len(frame) < 9 {
		return page, fmt.Errorf("modbus: short frame")
	}
	if binary.BigEndian.Uint16(frame[0:]) != txID || binary.BigEndian.Uint16(frame[2:]) != 0 {
		return page, fmt.Errorf("modbus: not our transaction")
	}
	length := int(binary.BigEndian.Uint16(frame[4:]))
	if length < 2 || 6+length > len(frame) {
		return page, fmt.Errorf("modbus: bad length")
	}
	if frame[6] != unit {
		return page, fmt.Errorf("modbus: answer from another unit")
	}
	pdu := frame[7 : 6+length]
	if pdu[0] == modbusFunction|0x80 {
		return page, errModbusException
	}
	if len(pdu) < 7 || pdu[0] != modbusFunction || pdu[1] != modbusMEIDeviceID {
		return page, fmt.Errorf("modbus: unexpected function")
	}
	page.Conformity = pdu[3]
	page.More = pdu[4] == 0xFF
	page.NextObject = pdu[5]
	n := int(pdu[6])
	page.Objects = map[byte]string{}
	rest := pdu[7:]
	for i := 0; i < n; i++ {
		if len(rest) < 2 || len(rest) < 2+int(rest[1]) {
			return page, fmt.Errorf("modbus: truncated object list")
		}
		id, l := rest[0], int(rest[1])
		page.Objects[id] = cleanString(string(rest[2 : 2+l]))
		rest = rest[2+l:]
	}
	return page, nil
}

// readModbusFrame reads one MBAP frame (header says how long).
func readModbusFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(hdr[4:]))
	if l < 2 || l > 254 {
		return nil, fmt.Errorf("modbus: bad length %d", l)
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// probeModbus asks one host for its device identification.
func probeModbus(ctx context.Context, lim *Limiter, addr netip.Addr, timeout time.Duration) (*proto.NetSurveyDevice, error) {
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, modbusPort).String())
	if err != nil {
		return nil, nil // nothing listening: not an error worth reporting
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	var tx uint16
	ask := func(unit, code, obj byte) (modbusDeviceIDPage, error) {
		if err := lim.Wait(ctx); err != nil {
			return modbusDeviceIDPage{}, err
		}
		tx++
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(modbusRequest(tx, unit, code, obj)); err != nil {
			return modbusDeviceIDPage{}, err
		}
		frame, err := readModbusFrame(conn)
		if err != nil {
			return modbusDeviceIDPage{}, err
		}
		return parseModbusResponse(frame, tx, unit)
	}

	objects := map[byte]string{}
	var unit byte
	var first modbusDeviceIDPage
	found := false
	for _, u := range []byte{0xFF, 0x00} {
		p, err := ask(u, modbusReadBasic, 0)
		if err == nil {
			unit, first, found = u, p, true
			break
		}
		if !errors.Is(err, errModbusException) {
			// A timeout or reset: the connection is no longer usable
			// for a second unit.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("modbus %s: %w", addr, err)
		}
	}
	if !found {
		return nil, nil // a Modbus server that does not implement 43/14
	}
	collect := func(p modbusDeviceIDPage, code byte) {
		for k, v := range p.Objects {
			objects[k] = v
		}
		for i := 0; p.More && i < modbusMaxPages; i++ {
			next, err := ask(unit, code, p.NextObject)
			if err != nil {
				return
			}
			for k, v := range next.Objects {
				objects[k] = v
			}
			p = next
		}
	}
	collect(first, modbusReadBasic)
	// Conformity level 0x02/0x82 and up also offers the regular objects.
	if first.Conformity&0x7F >= 0x02 {
		if p, err := ask(unit, modbusReadRegular, 0x03); err == nil {
			collect(p, modbusReadRegular)
		}
	}
	dev := &proto.NetSurveyDevice{IP: addr.String(), Protocols: []string{proto.NetSurveyModbus}}
	dev.Vendor = objects[0x00]
	dev.Firmware = objects[0x02]
	dev.Model = firstNonEmpty(objects[0x05], objects[0x04], objects[0x01])
	if code := objects[0x01]; code != "" {
		if n, err := strconv.Atoi(code); err == nil {
			dev.ProductCode = n
		} else if dev.Model != code {
			dev.Description = "product code " + code
		}
	}
	if name := objects[0x06]; name != "" {
		dev.Name = name
	}
	return dev, nil
}
