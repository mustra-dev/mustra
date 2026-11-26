package netsurvey

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The *.bin fixtures in testdata/ are real answers captured from protocol
// simulators (net-snmp, pymodbus, bacpypes3, cpppo, CUPS ippeveprinter)
// by TestSimulators with MUSTRA_NETSURVEY_CAPTURE. Profinet has no
// simulator; its frame is built here from the DCP specification.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The requests are pinned byte for byte: each is the only frame its
// protocol file can send, and the safety argument rests on what it is.
func TestRequestsAreExactlyTheIdentificationFrames(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		// MBAP tx 7, proto 0, len 5, unit 255; PDU 0x2B/0x0E read code 1 object 0.
		{"modbus 43/14", modbusRequest(7, 0xFF, modbusReadBasic, 0), "000700000005ff2b0e0100"},
		// BVLC unicast/broadcast, NPDU v1 no addressing, unconfirmed Who-Is.
		{"bacnet who-is unicast", bacnetWhoIs(false), "810a000801001008"},
		{"bacnet who-is broadcast", bacnetWhoIs(true), "810b000801001008"},
		// Encapsulation header: ListIdentity, length 0, session 0, status 0, context, options 0.
		{"enip list identity", enipListIdentityRequest(), "630000000000000000000000" + "6d75737472610000" + "00000000"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if fn := modbusRequest(1, 0, modbusReadRegular, 3)[7]; fn != 0x2B {
		t.Fatalf("modbus function %#x", fn)
	}
}

func TestModbusFixtures(t *testing.T) {
	p, err := parseModbusResponse(fixture(t, "modbus_basic.bin"), 1, 0xFF)
	if err != nil {
		t.Fatal(err)
	}
	if p.Objects[0] != "Acme Automation" || p.Objects[1] != "AC-PLC-200" || p.Objects[2] != "4.2.1" || p.More || p.Conformity&0x7F != 3 {
		t.Fatalf("basic: %+v", p)
	}
	p, err = parseModbusResponse(fixture(t, "modbus_regular.bin"), 2, 0xFF)
	if err != nil {
		t.Fatal(err)
	}
	if p.Objects[5] != "PLC-200" || p.Objects[6] != "line-3-controller" {
		t.Fatalf("regular: %+v", p)
	}
	// Someone else's transaction, another unit, an exception, a lie about length.
	if _, err := parseModbusResponse(fixture(t, "modbus_basic.bin"), 9, 0xFF); err == nil {
		t.Error("accepted another transaction's answer")
	}
	if _, err := parseModbusResponse(fixture(t, "modbus_basic.bin"), 1, 0); err == nil {
		t.Error("accepted another unit's answer")
	}
	if _, err := parseModbusResponse(mustHex(t, "000100000003ffab01"), 1, 0xFF); err != errModbusException {
		t.Errorf("exception: %v", err)
	}
	if _, err := parseModbusResponse(mustHex(t, "000100000040ff2b0e01"), 1, 0xFF); err == nil {
		t.Error("accepted a frame shorter than its length")
	}
	bad := append([]byte{}, fixture(t, "modbus_basic.bin")...)
	bad[15] = 0xF0 // first object claims 240 bytes
	if _, err := parseModbusResponse(bad, 1, 0xFF); err == nil {
		t.Error("accepted an object running past the frame")
	}
}

func TestBACnetFixture(t *testing.T) {
	iam, err := parseBACnetIAm(fixture(t, "bacnet_i_am.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if iam.Instance != 4711 || iam.VendorID != 999 || iam.MaxAPDU != 1024 {
		t.Fatalf("%+v", iam)
	}
	// Our own Who-Is is not an I-Am.
	if _, err := parseBACnetIAm(bacnetWhoIs(true)); err == nil {
		t.Error("parsed a Who-Is as an I-Am")
	}
	// The same I-Am arriving through a router (source network 5, MAC 0x07)
	// is not the device at that address.
	routed := mustHex(t, "810a001901080005010710"+"00c40200126722040091002203e7")
	routed[3] = byte(len(routed))
	if _, err := parseBACnetIAm(routed); err == nil {
		t.Error("accepted a routed I-Am")
	}
	// Forwarded-NPDU from a BBMD carries the original sender first.
	fwd := mustHex(t, "8104001b0a00000dbac0"+"01001000c40200126722040091002203e7")
	fwd[3] = byte(len(fwd))
	if iam, err := parseBACnetIAm(fwd); err != nil || iam.Instance != 4711 {
		t.Errorf("forwarded: %+v %v", iam, err)
	}
	// A length that disagrees with the datagram.
	short := append([]byte{}, fixture(t, "bacnet_i_am.bin")...)
	short[3]++
	if _, err := parseBACnetIAm(short); err == nil {
		t.Error("accepted a BVLC length mismatch")
	}
}

func TestENIPFixture(t *testing.T) {
	id, err := parseENIPListIdentity(fixture(t, "enip_list_identity.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if id.VendorID != 1 || id.DeviceType != 0x0E || id.ProductCode != 54 || id.Revision != "20.11" ||
		id.ProductName != "1756-L61/B LOGIX5561" || id.Serial != "006c061a" {
		t.Fatalf("%+v", id)
	}
	b := append([]byte{}, fixture(t, "enip_list_identity.bin")...)
	b[2] = 0xFF // length beyond the datagram
	if _, err := parseENIPListIdentity(b); err == nil {
		t.Error("accepted a truncated reply")
	}
	b = append([]byte{}, fixture(t, "enip_list_identity.bin")...)
	b[8] = 1 // non-zero status
	if _, err := parseENIPListIdentity(b); err == nil {
		t.Error("accepted an error status")
	}
}

func TestIPPRequestAndFixture(t *testing.T) {
	req := ippRequest("ipp://192.0.2.9:631/ipp/print", 3)
	// IPP/1.1, Get-Printer-Attributes, request 3, operation group.
	if !bytes.HasPrefix(req, mustHex(t, "0101000b0000000301")) || req[len(req)-1] != 0x03 {
		t.Fatalf("request header/end: %x", req)
	}
	r, err := parseIPPResponse(req)
	if err != nil {
		t.Fatalf("our own request does not parse: %v", err)
	}
	if len(r.Attrs["requested-attributes"]) != len(ippRequested) {
		t.Fatalf("requested-attributes: %+v", r.Attrs["requested-attributes"])
	}

	r, err = parseIPPResponse(fixture(t, "ipp_get_printer_attributes.bin"))
	if err != nil {
		t.Fatal(err)
	}
	d := r.device(netip.MustParseAddr("192.0.2.9"))
	if d.Model != "Example Corp LaserWriter 9000" || d.Vendor != "Example Corp" || d.PrinterState != "idle" || d.Firmware != "3.1.4" || d.Location != "Office 2" {
		t.Fatalf("%+v", d)
	}
	if len(d.Supplies) != 2 || d.Supplies[0] != (proto.NetSurveySupply{Name: "Black Toner", Percent: 80, Color: "#000000"}) || d.Supplies[1].Percent != 15 {
		t.Fatalf("supplies: %+v", d.Supplies)
	}
	if _, err := parseIPPResponse(fixture(t, "ipp_get_printer_attributes.bin")[:40]); err == nil {
		t.Error("accepted a truncated response")
	}
}

func TestSNMPFixture(t *testing.T) {
	g := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}
	pkt, err := g.SnmpDecodePacket(fixture(t, "snmp_v2c_system.bin"))
	if err != nil {
		t.Fatal(err)
	}
	var d proto.NetSurveyDevice
	applySystem(&d, pkt.Variables)
	if d.Name != "lab-printer-01" || d.Vendor != "HP" || d.ObjectID != "1.3.6.1.4.1.11.2.3.9.1" || d.Services != 72 ||
		d.Location != "Lab rack 3" || d.Description != "HP LaserJet simulated printer (net-snmp)" || d.UptimeSeconds <= 0 {
		t.Fatalf("%+v", d)
	}
	if supplyPercent(4500, 9000) != 50 || supplyPercent(-3, 9000) != -1 || supplyPercent(10, -2) != -1 || supplyPercent(12, 10) != 100 {
		t.Error("supply levels")
	}
	if _, _, err := snmpUSM(proto.NetSurveyCred{Version: "3", User: "u", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassphrase: "x"}); err == nil {
		t.Error("authPriv without a privacy passphrase was accepted")
	}
}

func TestProfinetFrames(t *testing.T) {
	src := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	req := dcpIdentifyAll(src, 0x01020304)
	want := "010ecf000000" + "020000000001" + "8892" + "fefe" + "05" + "00" + "01020304" + "0001" + "0004" + "ffff" + "0000"
	if got := hex.EncodeToString(req[:30]); got != want || len(req) != 60 {
		t.Fatalf("identify-all: %s (len %d)", got, len(req))
	}
	// An Identify response built from the DCP specification: name of
	// station "plc-1", vendor text "S7-1500", vendor 0x002a device 0x0e0f,
	// role IO-controller, IP 192.0.2.50/24.
	blocks := "0202" + "0007" + "0000" + "706c632d31" + "00" + // name of station (odd: padded)
		"0201" + "0009" + "0000" + "53372d31353030" + "00" + // vendor text
		"0203" + "0006" + "0000" + "002a0e0f" +
		"0204" + "0004" + "0000" + "0200" +
		"0102" + "000e" + "0001" + "c0000232" + "ffffff00" + "c0000201"
	frame := mustHex(t, "020000000001"+"0a0b0c0d0e0f"+"8892"+"feff"+"0501"+"01020304"+"0000"+
		hex.EncodeToString([]byte{0, byte(len(mustHex(t, blocks)))})+blocks)
	d, err := parseDCPIdentify(frame, 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	if d.StationName != "plc-1" || d.VendorText != "S7-1500" || d.VendorID != 0x2a || d.DeviceID != 0x0e0f ||
		d.Role != "io-controller" || d.IP.String() != "192.0.2.50" || d.MAC.String() != "0a:0b:0c:0d:0e:0f" {
		t.Fatalf("%+v", d)
	}
	if pd := d.device(); pd.Vendor != "Siemens" || pd.IP != "192.0.2.50" || pd.Name != "plc-1" {
		t.Fatalf("%+v", pd)
	}
	if _, err := parseDCPIdentify(frame, 0x0badf00d); err == nil {
		t.Error("accepted another request's answer")
	}
	if _, err := parseDCPIdentify(req, 0x01020304); err == nil {
		t.Error("parsed a request as a response")
	}
}

func TestCleanString(t *testing.T) {
	if got := cleanString("  Acme\x00\x00 <PLC>\x1b[31m\nline\xff "); got != "Acme <PLC>[31m line" {
		t.Fatalf("%q", got)
	}
	long := bytes.Repeat([]byte("é"), 300)
	if got := cleanString(string(long)); len(got) > 256 || !utf8Valid(got) {
		t.Fatalf("len %d", len(got))
	}
}

func utf8Valid(s string) bool { return bytes.Equal([]byte(s), []byte(string([]rune(s)))) }
