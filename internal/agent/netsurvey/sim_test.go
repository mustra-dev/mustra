package netsurvey

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mustra-dev/mustra/internal/proto"
)

// TestSimulators runs a real survey against protocol simulators. It is
// opt-in: it needs the simulators up on an isolated network, and runs from
// a container on that network. test/netsurvey/run.sh does all of that
// (docs/DEVELOPMENT.md, "Network survey simulators"):
//
//	MUSTRA_NETSURVEY_SIM=<subnet> MUSTRA_NETSURVEY_SIM_HOSTS=snmp=IP,modbus=IP,bacnet=IP,enip=IP,ipp=IP
//
// MUSTRA_NETSURVEY_CAPTURE=<dir> also writes each protocol's raw answer
// there, which is where the fixtures in testdata/ came from.
func TestSimulators(t *testing.T) {
	subnet := os.Getenv("MUSTRA_NETSURVEY_SIM")
	if subnet == "" {
		t.Skip("set MUSTRA_NETSURVEY_SIM to run against protocol simulators")
	}
	hosts := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("MUSTRA_NETSURVEY_SIM_HOSTS"), ",") {
		k, v, _ := strings.Cut(kv, "=")
		hosts[k] = v
	}
	if dir := os.Getenv("MUSTRA_NETSURVEY_CAPTURE"); dir != "" {
		capture(t, dir, hosts)
		if os.Getenv("MUSTRA_NETSURVEY_CAPTURE_ONLY") != "" {
			return
		}
	}

	for _, cred := range []proto.NetSurveyCred{
		{Version: "2c", Community: "surveycomm"},
		{Version: "3", User: "surveyor", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassphrase: "authpass-123", PrivProtocol: "AES", PrivPassphrase: "privpass-456"},
	} {
		t.Run("snmp-v"+cred.Version, func(t *testing.T) {
			job := proto.NetSurveyJob{RunID: "run-sim", Subnets: []string{subnet}, Protocols: proto.NetSurveyProtocols,
				PacketsPerSecond: 200, Concurrency: 32, TimeoutMillis: 800, BudgetSeconds: 300, SNMP: &cred}
			start := time.Now()
			rep := Run(context.Background(), job, Env{Networks: LocalNetworks})
			raw, _ := json.MarshalIndent(rep, "", "  ")
			t.Logf("survey took %s, %d probes:\n%s", time.Since(start).Round(time.Millisecond), rep.Probes, raw)
			if strings.Contains(string(raw), "authpass-123") || strings.Contains(string(raw), "surveycomm") {
				t.Fatal("a credential appears in the report")
			}
			by := map[string]proto.NetSurveyDevice{}
			for _, d := range rep.Devices {
				by[d.IP] = d
			}
			if d := by[hosts["snmp"]]; d.Name != "lab-printer-01" || d.Vendor != "HP" || len(d.Supplies) != 2 || d.Supplies[0].Percent != 50 || d.Serial != "CNB1234567" {
				t.Errorf("snmp device: %+v", d)
			}
			if d := by[hosts["modbus"]]; d.Vendor != "Acme Automation" || d.Model != "PLC-200" || d.Firmware != "4.2.1" {
				t.Errorf("modbus device: %+v", d)
			}
			if d := by[hosts["bacnet"]]; d.BACnetInstance == nil || *d.BACnetInstance != 4711 {
				t.Errorf("bacnet device: %+v", d)
			}
			if d := by[hosts["enip"]]; d.Model == "" || !contains(d.Protocols, proto.NetSurveyENIP) {
				t.Errorf("enip device: %+v", d)
			}
			if d := by[hosts["ipp"]]; !strings.Contains(d.Model, "LaserWriter 9000") || d.PrinterState != "idle" || len(d.Supplies) != 2 || d.Supplies[1].Percent != 15 || d.Firmware != "3.1.4" {
				t.Errorf("ipp device: %+v", d)
			}
			// Nothing outside the subnet, ever.
			pfx := netip.MustParsePrefix(subnet)
			for _, d := range rep.Devices {
				if a, err := netip.ParseAddr(d.IP); err == nil && !pfx.Contains(a) {
					t.Errorf("device outside the survey's subnet: %s", d.IP)
				}
			}
		})
	}

	t.Run("refuses an off-link subnet", func(t *testing.T) {
		job := proto.NetSurveyJob{RunID: "run-sim", Subnets: []string{"198.51.100.0/24"}, Protocols: []string{proto.NetSurveyModbus}}
		rep := Run(context.Background(), job, Env{Networks: LocalNetworks})
		if rep.Probes != 0 || len(rep.Refused) != 1 || rep.Error == "" {
			t.Fatalf("an off-link subnet was not refused: %+v", rep)
		}
	})
}

// capture writes each simulator's raw answer to the request this package
// sends, for the fixtures.
func capture(t *testing.T, dir string, hosts map[string]string) {
	t.Helper()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	timeout := 2 * time.Second
	if h := hosts["modbus"]; h != "" {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(h, "502"), timeout)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(timeout))
			_, _ = c.Write(modbusRequest(1, 0xFF, modbusReadBasic, 0))
			if f, err := readModbusFrame(c); err == nil {
				write("modbus_basic.bin", f)
			}
			_, _ = c.Write(modbusRequest(2, 0xFF, modbusReadRegular, 3))
			if f, err := readModbusFrame(c); err == nil {
				write("modbus_regular.bin", f)
			}
			c.Close()
		}
	}
	if h := hosts["enip"]; h != "" {
		c, err := net.DialTimeout("udp", net.JoinHostPort(h, "44818"), timeout)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(timeout))
			_, _ = c.Write(enipListIdentityRequest())
			buf := make([]byte, 1500)
			if n, err := c.Read(buf); err == nil {
				write("enip_list_identity.bin", buf[:n])
			}
			c.Close()
		}
	}
	if h := hosts["bacnet"]; h != "" {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: bacnetPort})
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(timeout))
			_, _ = c.WriteToUDP(bacnetWhoIs(false), &net.UDPAddr{IP: net.ParseIP(h), Port: bacnetPort})
			buf := make([]byte, 1500)
			for {
				n, from, err := c.ReadFromUDP(buf)
				if err != nil {
					break
				}
				if from.IP.String() == h {
					write("bacnet_i_am.bin", buf[:n])
					break
				}
			}
			c.Close()
		}
	}
	if h := hosts["snmp"]; h != "" {
		pkt := gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "surveycomm", PDUType: gosnmp.GetRequest, RequestID: 1}
		for _, o := range []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidSysLocation, oidSysServices} {
			pkt.Variables = append(pkt.Variables, gosnmp.SnmpPDU{Name: o, Type: gosnmp.Null})
		}
		req, err := pkt.MarshalMsg()
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.DialTimeout("udp", net.JoinHostPort(h, "161"), timeout)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(timeout))
			_, _ = c.Write(req)
			buf := make([]byte, 1500)
			if n, err := c.Read(buf); err == nil {
				write("snmp_v2c_system.bin", buf[:n])
			}
			c.Close()
		}
	}
	if h := hosts["ipp"]; h != "" {
		c, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(h, "631"))
		if err == nil {
			body := ippRequest("ipp://"+h+":631/ipp/print", 1)
			req := "POST /ipp/print HTTP/1.1\r\nHost: " + h + ":631\r\nContent-Type: application/ipp\r\nConnection: close\r\nContent-Length: " +
				itoa(len(body)) + "\r\n\r\n"
			_ = c.SetDeadline(time.Now().Add(timeout))
			_, _ = c.Write(append([]byte(req), body...))
			var all []byte
			buf := make([]byte, 65536)
			for {
				n, err := c.Read(buf)
				all = append(all, buf[:n]...)
				if err != nil {
					break
				}
			}
			if i := strings.Index(string(all), "\r\n\r\n"); i > 0 {
				write("ipp_get_printer_attributes.http", all)
			}
			c.Close()
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
