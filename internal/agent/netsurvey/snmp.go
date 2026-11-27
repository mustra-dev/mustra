package netsurvey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mustra-dev/mustra/internal/proto"
)

// SNMP v2c/v3: GET of the system group, then bounded GETNEXT walks of the
// interface table, Printer-MIB supplies and a few ENTITY-MIB columns.
//
// Why this is safe: GET and GETNEXT read. A SET request is never built
// (gosnmp only sends one from its Set method, which this package does not
// call), so a community or user with write access still cannot change
// anything through a survey. Every walk stops after a fixed number of
// rows, and retries are off: one packet per request, each through the
// run's rate limiter.

const (
	snmpPort       = 161
	snmpMaxIfRows  = 64
	snmpMaxSupply  = 32
	snmpMaxEntRows = 16
)

const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation = ".1.3.6.1.2.1.1.6.0"
	oidSysServices = ".1.3.6.1.2.1.1.7.0"

	oidIfDescr       = ".1.3.6.1.2.1.2.2.1.2"
	oidIfPhysAddress = ".1.3.6.1.2.1.2.2.1.6"
	oidIfOperStatus  = ".1.3.6.1.2.1.2.2.1.8"

	oidSupplyDesc  = ".1.3.6.1.2.1.43.11.1.1.6"
	oidSupplyMax   = ".1.3.6.1.2.1.43.11.1.1.8"
	oidSupplyLevel = ".1.3.6.1.2.1.43.11.1.1.9"
	oidPrtSerial   = ".1.3.6.1.2.1.43.5.1.1.17"
	oidHrDevType   = ".1.3.6.1.2.1.25.3.2.1.2"
	oidHrDevDescr  = ".1.3.6.1.2.1.25.3.2.1.3"
	// hrDevicePrinter, the hrDeviceType value of the printer row.
	oidHrDevicePrinter = ".1.3.6.1.2.1.25.3.1.5"

	oidEntSoftwareRev = ".1.3.6.1.2.1.47.1.1.1.1.10"
	oidEntSerial      = ".1.3.6.1.2.1.47.1.1.1.1.11"
	oidEntModelName   = ".1.3.6.1.2.1.47.1.1.1.1.13"
)

var errStopWalk = errors.New("enough rows")

// snmpClient builds a client for one host from the job's credential.
func snmpClient(ctx context.Context, lim *Limiter, cred proto.NetSurveyCred, addr netip.Addr, timeout time.Duration) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{
		Target: addr.String(), Port: snmpPort, Transport: "udp",
		Context: ctx, Timeout: timeout, Retries: 0, MaxOids: 8,
		// Every request, discovery included, waits its turn.
		PreSend: func(*gosnmp.GoSNMP) { _ = lim.Wait(ctx) },
	}
	switch cred.Version {
	case "2c", "":
		if cred.Community == "" {
			return nil, fmt.Errorf("SNMP v2c needs a community")
		}
		g.Version = gosnmp.Version2c
		g.Community = cred.Community
	case "3":
		usm, flags, err := snmpUSM(cred)
		if err != nil {
			return nil, err
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = flags
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("unsupported SNMP version %q", cred.Version)
	}
	return g, nil
}

var snmpAuthProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
}

var snmpPrivProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192, "AES256": gosnmp.AES256,
	"AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C,
}

func snmpUSM(c proto.NetSurveyCred) (*gosnmp.UsmSecurityParameters, gosnmp.SnmpV3MsgFlags, error) {
	if c.User == "" {
		return nil, 0, fmt.Errorf("SNMPv3 needs a user")
	}
	usm := &gosnmp.UsmSecurityParameters{UserName: c.User}
	switch c.SecurityLevel {
	case "noAuthNoPriv":
		return usm, gosnmp.NoAuthNoPriv, nil
	case "authNoPriv", "authPriv", "":
	default:
		return nil, 0, fmt.Errorf("unknown SNMPv3 security level %q", c.SecurityLevel)
	}
	ap, ok := snmpAuthProtocols[strings.ToUpper(c.AuthProtocol)]
	if !ok || c.AuthPassphrase == "" {
		return nil, 0, fmt.Errorf("SNMPv3 authentication needs a protocol and passphrase")
	}
	usm.AuthenticationProtocol, usm.AuthenticationPassphrase = ap, c.AuthPassphrase
	if c.SecurityLevel == "authNoPriv" {
		return usm, gosnmp.AuthNoPriv, nil
	}
	pp, ok := snmpPrivProtocols[strings.ToUpper(c.PrivProtocol)]
	if !ok || c.PrivPassphrase == "" {
		return nil, 0, fmt.Errorf("SNMPv3 privacy needs a protocol and passphrase")
	}
	usm.PrivacyProtocol, usm.PrivacyPassphrase = pp, c.PrivPassphrase
	return usm, gosnmp.AuthPriv, nil
}

// probeSNMP reads one host. A host that does not answer the system group
// is not an SNMP device (or the credential is wrong): no error, no device.
func probeSNMP(ctx context.Context, lim *Limiter, cred proto.NetSurveyCred, addr netip.Addr, timeout time.Duration) (*proto.NetSurveyDevice, error) {
	g, err := snmpClient(ctx, lim, cred, addr, timeout)
	if err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, nil
	}
	defer g.Conn.Close()
	pkt, err := g.Get([]string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidSysLocation, oidSysServices})
	if err != nil || pkt == nil || pkt.Error != gosnmp.NoError {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	d := &proto.NetSurveyDevice{IP: addr.String(), Protocols: []string{proto.NetSurveySNMP}}
	applySystem(d, pkt.Variables)

	// Interfaces: three columns walked in step, joined on the row index.
	ifs := map[string]*proto.NetSurveyInterface{}
	var order []string
	row := func(idx string) *proto.NetSurveyInterface {
		if r, ok := ifs[idx]; ok {
			return r
		}
		if len(order) >= snmpMaxIfRows {
			return nil
		}
		r := &proto.NetSurveyInterface{}
		ifs[idx] = r
		order = append(order, idx)
		return r
	}
	walkColumn(g, oidIfDescr, snmpMaxIfRows, func(idx string, p gosnmp.SnmpPDU) {
		if r := row(idx); r != nil {
			r.Name = pduString(p)
		}
	})
	if len(order) > 0 {
		walkColumn(g, oidIfPhysAddress, snmpMaxIfRows, func(idx string, p gosnmp.SnmpPDU) {
			if r, ok := ifs[idx]; ok {
				r.MAC = pduMAC(p)
			}
		})
		walkColumn(g, oidIfOperStatus, snmpMaxIfRows, func(idx string, p gosnmp.SnmpPDU) {
			if r, ok := ifs[idx]; ok {
				r.Status = ifOperStatus(pduInt(p))
			}
		})
	}
	for _, idx := range order {
		d.Interfaces = append(d.Interfaces, *ifs[idx])
	}

	// Printer-MIB: present on printers only; the first walk says whether.
	type supply struct {
		name       string
		max, level int
	}
	supplies := map[string]*supply{}
	var sOrder []string
	walkColumn(g, oidSupplyDesc, snmpMaxSupply, func(idx string, p gosnmp.SnmpPDU) {
		supplies[idx] = &supply{name: pduString(p), max: -1, level: -1}
		sOrder = append(sOrder, idx)
	})
	if len(sOrder) > 0 {
		walkColumn(g, oidSupplyMax, snmpMaxSupply, func(idx string, p gosnmp.SnmpPDU) {
			if s, ok := supplies[idx]; ok {
				s.max = pduInt(p)
			}
		})
		walkColumn(g, oidSupplyLevel, snmpMaxSupply, func(idx string, p gosnmp.SnmpPDU) {
			if s, ok := supplies[idx]; ok {
				s.level = pduInt(p)
			}
		})
		for _, idx := range sOrder {
			s := supplies[idx]
			d.Supplies = append(d.Supplies, proto.NetSurveySupply{Name: s.name, Percent: supplyPercent(s.level, s.max)})
		}
		d.Serial = firstColumnValue(g, oidPrtSerial)
		if d.Model == "" {
			d.Model = printerModel(g)
		}
	}

	// ENTITY-MIB: switches and routers name their model, serial and
	// software there; the first non-empty row is the chassis.
	if d.Model == "" {
		d.Model = firstColumnValue(g, oidEntModelName)
	}
	if d.Serial == "" {
		d.Serial = firstColumnValue(g, oidEntSerial)
	}
	if d.Firmware == "" {
		d.Firmware = firstColumnValue(g, oidEntSoftwareRev)
	}
	return d, ctx.Err()
}

// applySystem maps the system group onto the device.
func applySystem(d *proto.NetSurveyDevice, vars []gosnmp.SnmpPDU) {
	for _, v := range vars {
		if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.EndOfMibView {
			continue
		}
		switch normalizeOID(v.Name) {
		case oidSysDescr:
			d.Description = truncate(pduString(v), 512)
		case oidSysObjectID:
			d.ObjectID = strings.TrimPrefix(pduString(v), ".")
			d.Vendor = enterpriseVendor(d.ObjectID)
		case oidSysUpTime:
			d.UptimeSeconds = int64(pduInt(v)) / 100
		case oidSysName:
			d.Name = pduString(v)
		case oidSysLocation:
			d.Location = pduString(v)
		case oidSysServices:
			d.Services = pduInt(v)
		}
	}
}

// walkColumn walks one table column with GETNEXT, at most max rows, and
// hands each row's index to fn.
func walkColumn(g *gosnmp.GoSNMP, column string, max int, fn func(idx string, p gosnmp.SnmpPDU)) {
	n := 0
	_ = g.Walk(column, func(p gosnmp.SnmpPDU) error {
		name := normalizeOID(p.Name)
		if !strings.HasPrefix(name, column+".") {
			return errStopWalk
		}
		fn(strings.TrimPrefix(name, column+"."), p)
		n++
		if n >= max {
			return errStopWalk
		}
		return nil
	})
}

func firstColumnValue(g *gosnmp.GoSNMP, column string) string {
	out := ""
	walkColumn(g, column, snmpMaxEntRows, func(_ string, p gosnmp.SnmpPDU) {
		if out == "" {
			out = pduString(p)
		}
	})
	return out
}

// printerModel is the hrDeviceDescr of the hrDeviceTable row whose type
// is hrDevicePrinter: the first row is often the CPU.
func printerModel(g *gosnmp.GoSNMP) string {
	idx := ""
	walkColumn(g, oidHrDevType, snmpMaxEntRows, func(i string, p gosnmp.SnmpPDU) {
		if idx == "" && normalizeOID(pduString(p)) == oidHrDevicePrinter {
			idx = i
		}
	})
	if idx == "" {
		return ""
	}
	pkt, err := g.Get([]string{oidHrDevDescr + "." + idx})
	if err != nil || pkt == nil || len(pkt.Variables) != 1 || pkt.Variables[0].Type != gosnmp.OctetString {
		return ""
	}
	return pduString(pkt.Variables[0])
}

func normalizeOID(o string) string {
	if !strings.HasPrefix(o, ".") {
		return "." + o
	}
	return o
}

func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		return cleanString(string(v))
	case string:
		return cleanString(v)
	case nil:
		return ""
	default:
		return cleanString(fmt.Sprint(v))
	}
}

func pduInt(p gosnmp.SnmpPDU) int {
	if b := gosnmp.ToBigInt(p.Value); b != nil && b.IsInt64() {
		return int(b.Int64())
	}
	return 0
}

func pduMAC(p gosnmp.SnmpPDU) string {
	b, ok := p.Value.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}
	return strings.ToLower(net.HardwareAddr(b).String())
}

var ifStatuses = map[int]string{1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "not present", 7: "lower layer down"}

func ifOperStatus(v int) string { return ifStatuses[v] }

// supplyPercent reads Printer-MIB levels: -1 other, -2 unknown, -3 "some
// remaining"; max -1/-2 likewise. Anything not computable is -1.
func supplyPercent(level, max int) int {
	if level < 0 || max <= 0 {
		return -1
	}
	if level > max {
		return 100
	}
	return level * 100 / max
}

// enterpriseVendors names the IANA private enterprise numbers a survey
// meets most (1.3.6.1.4.1.<n> in sysObjectID).
var enterpriseVendors = map[int]string{
	9: "Cisco", 11: "HP", 236: "Samsung", 253: "Xerox", 318: "APC", 367: "Ricoh", 641: "Lexmark",
	674: "Dell", 1248: "Epson", 1347: "Kyocera", 1602: "Canon", 1916: "Extreme Networks", 2011: "Huawei",
	2435: "Brother", 2636: "Juniper", 3375: "F5", 4526: "Netgear", 6574: "Synology", 6876: "VMware",
	8072: "Net-SNMP", 11863: "TP-Link", 12356: "Fortinet", 14988: "MikroTik", 18334: "Konica Minolta",
	24681: "QNAP", 25461: "Palo Alto Networks", 30065: "Arista", 41112: "Ubiquiti",
}

func enterpriseVendor(oid string) string {
	rest, ok := strings.CutPrefix(oid, "1.3.6.1.4.1.")
	if !ok {
		return ""
	}
	num, _, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(num)
	if err != nil {
		return ""
	}
	return enterpriseVendors[n]
}
