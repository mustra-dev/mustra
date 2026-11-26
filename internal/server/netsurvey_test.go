package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

const testAgent = "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"

func strp(s string) *string { return &s }

func validSurvey() netSurveyRequest {
	return netSurveyRequest{Name: "line 3", AgentIDs: []string{testAgent}, Subnets: []string{"10.40.7.0/24"},
		Protocols: []string{"modbus", "enip"}}
}

func TestBuildNetSurveyValidates(t *testing.T) {
	n, _, err := buildNetSurvey(validSurvey(), nil, netSurveySecrets{})
	if err != nil {
		t.Fatal(err)
	}
	// Off unless asked, and the safe defaults filled in.
	if n.Enabled || n.PacketsPerSecond != 20 || n.Concurrency != 8 || n.TimeoutMillis != 1500 || n.BudgetSeconds != 900 || n.IntervalHours != 0 {
		t.Fatalf("defaults: %+v", n)
	}
	bad := []func(r *netSurveyRequest){
		func(r *netSurveyRequest) { r.Name = "" },
		func(r *netSurveyRequest) { r.AgentIDs = nil },
		func(r *netSurveyRequest) { r.AgentIDs = []string{"agt-../../x"} },
		func(r *netSurveyRequest) { r.Subnets = nil },
		func(r *netSurveyRequest) { r.Subnets = []string{"10.0.0.0/16"} }, // larger than /22
		func(r *netSurveyRequest) { r.Subnets = []string{"2001:db8::/120"} },
		func(r *netSurveyRequest) { r.Subnets = []string{"224.0.0.0/24"} },
		func(r *netSurveyRequest) { r.Protocols = nil },
		func(r *netSurveyRequest) { r.Protocols = []string{"modbus-write"} },
		func(r *netSurveyRequest) { r.PacketsPerSecond = 5000 },
		func(r *netSurveyRequest) { r.Concurrency = 100 },
		func(r *netSurveyRequest) { r.TimeoutMillis = 60000 },
		func(r *netSurveyRequest) { r.BudgetSeconds = 86400 },
		func(r *netSurveyRequest) { r.IntervalHours = -1 },
		func(r *netSurveyRequest) { r.Protocols = []string{"snmp"} }, // no SNMP settings
		func(r *netSurveyRequest) {
			r.Protocols = []string{"snmp"}
			r.SNMP = &netSurveySNMPRequest{Version: "2c"} // no community
		},
		func(r *netSurveyRequest) {
			r.SNMP = &netSurveySNMPRequest{Version: "3", User: "u", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassphrase: strp("long-enough")}
		},
		func(r *netSurveyRequest) {
			r.SNMP = &netSurveySNMPRequest{Version: "3", User: "u", SecurityLevel: "authNoPriv", AuthProtocol: "SHA", AuthPassphrase: strp("short")}
		},
		func(r *netSurveyRequest) { r.SNMP = &netSurveySNMPRequest{Version: "1", Community: strp("public")} },
	}
	for i, mutate := range bad {
		r := validSurvey()
		mutate(&r)
		if _, _, err := buildNetSurvey(r, nil, netSurveySecrets{}); err == nil {
			t.Errorf("case %d was accepted: %+v", i, r)
		}
	}
}

func TestBuildNetSurveyKeepsAndClearsSecrets(t *testing.T) {
	r := validSurvey()
	r.Protocols = []string{"snmp"}
	r.SNMP = &netSurveySNMPRequest{Version: "2c", Community: strp("plant-ro")}
	n, sec, err := buildNetSurvey(r, nil, netSurveySecrets{})
	if err != nil || sec.Community != "plant-ro" {
		t.Fatalf("%v %+v", err, sec)
	}
	// An edit that leaves the community out keeps it.
	r.SNMP = &netSurveySNMPRequest{Version: "2c"}
	if _, sec, err = buildNetSurvey(r, &n, sec); err != nil || sec.Community != "plant-ro" {
		t.Fatalf("kept: %v %+v", err, sec)
	}
	// Switching to v3 drops the community.
	r.SNMP = &netSurveySNMPRequest{Version: "3", User: "u", SecurityLevel: "authPriv", AuthProtocol: "sha256",
		AuthPassphrase: strp("auth-pass-1"), PrivProtocol: "aes", PrivPassphrase: strp("priv-pass-1")}
	n, sec, err = buildNetSurvey(r, &n, sec)
	if err != nil || sec.Community != "" || sec.Auth != "auth-pass-1" || n.SNMPAuthProtocol != "SHA256" || n.SNMPPrivProtocol != "AES" {
		t.Fatalf("v3: %v %+v %+v", err, sec, n)
	}
	// Dropping SNMP altogether clears everything.
	r.Protocols, r.SNMP = []string{"ipp"}, nil
	if n, sec, err = buildNetSurvey(r, &n, sec); err != nil || !sec.empty() || n.SNMPVersion != "" {
		t.Fatalf("cleared: %v %+v %+v", err, sec, n)
	}
}

// The secrets are sealed, bound to their survey, and never in an answer.
func TestNetSurveySecretsAreSealedAndRedacted(t *testing.T) {
	v, err := vault.New(nil, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{vault: v}
	sec := netSurveySecrets{Community: "s3cret-community", Auth: "s3cret-auth", Priv: "s3cret-priv"}
	ct, err := s.sealSurveySecrets("nsv-a", sec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ct), "s3cret") {
		t.Fatal("secrets stored in the clear")
	}
	got, err := s.openSurveySecrets(&store.NetworkSurvey{ID: "nsv-a", SNMPSecretEnc: ct})
	if err != nil || got != sec {
		t.Fatalf("open: %v %+v", err, got)
	}
	// Copied onto another survey's row, the blob does not open.
	if _, err := s.openSurveySecrets(&store.NetworkSurvey{ID: "nsv-b", SNMPSecretEnc: ct}); err == nil {
		t.Fatal("secrets opened under another survey")
	}
	// No vault, no secrets: refused rather than stored in the clear.
	if _, err := (&Server{}).sealSurveySecrets("nsv-a", sec); err == nil {
		t.Fatal("sealed without a vault")
	}

	// What the API shows for such a survey says "set", never the value.
	view := netSurveySNMPView{Version: "3", User: "u", SecurityLevel: "authPriv", AuthPassphraseSet: true, PrivPassphraseSet: true}
	raw, _ := json.Marshal(listNetSurveysResponse{Surveys: []netSurveyView{{ID: "nsv-a", SNMP: &view}}})
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "passphrase\":\"") {
		t.Fatalf("list answer: %s", raw)
	}
	// And the job's own formatting hides them too (log lines, %v).
	cred := proto.NetSurveyCred{Version: "2c", Community: "s3cret-community"}
	if strings.Contains(cred.String(), "s3cret") {
		t.Fatal("credential formatted with its secret")
	}
}

func TestOffLinkSubnets(t *testing.T) {
	ifaces := []proto.NetworkInterfaceInfo{
		{Name: "lo", Addresses: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Addresses: []string{"10.40.7.12/24", "fe80::1/64"}},
		{Name: "eth1", Addresses: []string{"172.16.0.5/16"}},
	}
	got := offLinkSubnets([]string{"10.40.7.0/24", "10.40.7.128/25", "172.16.4.0/22", "10.40.8.0/24", "192.168.1.0/24"}, ifaces)
	if !slices.Equal(got, []string{"10.40.8.0/24", "192.168.1.0/24"}) {
		t.Fatalf("%v", got)
	}
}

func TestSurveyReportOutcomeDropsOutOfScopeAnswers(t *testing.T) {
	run := store.NetworkSurveyRun{ID: "nsr-1", Subnets: []string{"10.40.7.0/24"}}
	rep := proto.NetSurveyReport{RunID: "nsr-1", HostsPlanned: 253, Probes: 900, Devices: []proto.NetSurveyDevice{
		{IP: "10.40.7.20", MAC: "AA:BB:CC:00:11:22", Protocols: []string{"ipp"}},
		{IP: "10.40.8.20", Protocols: []string{"snmp"}},             // another subnet
		{IP: "not-an-ip", Protocols: []string{"snmp"}},              // nonsense
		{MAC: "02:00:00:00:00:09", Protocols: []string{"profinet"}}, // layer 2, no address yet
		{Protocols: []string{"profinet"}},                           // neither
		{IP: "10.40.7.20", MAC: "aa:bb:cc:00:11:22"},                // a duplicate
	}}
	status, detail, keep, dropped := surveyReportOutcome(run, rep)
	if status != "succeeded" || len(keep) != 2 || dropped != 4 || !strings.Contains(detail, "outside") {
		t.Fatalf("%s %q keep=%d dropped=%d", status, detail, len(keep), dropped)
	}
	if keep[0].MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("MAC not normalised: %q", keep[0].MAC)
	}

	status, _, _, _ = surveyReportOutcome(run, proto.NetSurveyReport{Error: "no subnet in this survey may be surveyed from this endpoint",
		Refused: []proto.NetSurveyRefusal{{Subnet: "10.40.7.0/24", Reason: "not a network this endpoint is directly attached to"}}})
	if status != "refused" {
		t.Fatalf("all refused: %s", status)
	}
	if status, _, _, _ = surveyReportOutcome(run, proto.NetSurveyReport{TimedOut: true}); status != "timed_out" {
		t.Fatalf("timed out: %s", status)
	}
	if status, _, _, _ = surveyReportOutcome(run, proto.NetSurveyReport{Cancelled: true}); status != "cancelled" {
		t.Fatalf("cancelled: %s", status)
	}
}

func TestClassifyDevice(t *testing.T) {
	cases := []struct {
		d    proto.NetSurveyDevice
		want string
	}{
		{proto.NetSurveyDevice{Protocols: []string{"ipp"}}, devTypePrinter},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Supplies: []proto.NetSurveySupply{{Name: "toner"}}}, devTypePrinter},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Description: "Cisco IOS Software, C2960 Software", Services: 2}, devTypeSwitch},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Description: "RouterOS CCR1009", Services: 78}, devTypeRouter},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Services: 6}, devTypeRouter},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Description: "Linux nas01 5.10", Vendor: "Synology"}, devTypeNAS},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Vendor: "APC", Description: "APC Web/SNMP Management Card"}, devTypeUPS},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}, Description: "Linux web-01 6.1.0", Services: 72}, devTypeHost},
		{proto.NetSurveyDevice{Protocols: []string{"snmp", "enip"}, DeviceTypeCode: 0x0E, Description: "Linux"}, devTypePLC},
		{proto.NetSurveyDevice{Protocols: []string{"enip"}, DeviceTypeCode: 0x18}, devTypeHMI},
		{proto.NetSurveyDevice{Protocols: []string{"profinet"}, DeviceRole: "io-controller"}, devTypePLC},
		{proto.NetSurveyDevice{Protocols: []string{"profinet"}, DeviceRole: "io-device"}, devTypeIO},
		{proto.NetSurveyDevice{Protocols: []string{"bacnet"}}, devTypeBuilding},
		{proto.NetSurveyDevice{Protocols: []string{"modbus"}, Model: "PLC-200"}, devTypePLC},
		{proto.NetSurveyDevice{Protocols: []string{"modbus"}, Model: "Energy meter"}, devTypeIndustrial},
		{proto.NetSurveyDevice{Protocols: []string{"snmp"}}, devTypeOther},
	}
	for _, c := range cases {
		if got := classifyDevice(c.d); got != c.want {
			t.Errorf("%+v: %s, want %s", c.d, got, c.want)
		}
	}
}

func TestMergeSurveyDevices(t *testing.T) {
	now := time.Now()
	dev := func(key, mac, ip, typ string, d proto.NetSurveyDevice, seen time.Time) store.NetworkSurveyDevice {
		raw, _ := json.Marshal(d)
		return store.NetworkSurveyDevice{Key: key, MAC: mac, IP: ip, DeviceType: typ, Device: raw, AgentID: testAgent, LastSeen: seen}
	}
	hosts := []discoveredHost{
		{IP: "10.40.7.20", MAC: "3c:2a:f4:6b:91:0e", SeenBy: []string{"FIN-LT-0142"}, SeenCount: 1},
		{IP: "10.40.7.30", MAC: "00:11:22:33:44:55"},
		{IP: "10.40.7.40", MAC: ""},
	}
	devs := []store.NetworkSurveyDevice{
		// By MAC, though the address moved.
		dev("3c:2a:f4:6b:91:0e", "3c:2a:f4:6b:91:0e", "10.40.7.21", devTypePrinter, proto.NetSurveyDevice{Model: "HL-L2350DW", Vendor: "Brother"}, now),
		// An older answer for the same device loses to the newer one.
		dev("ip:10.40.7.20", "", "10.40.7.20", devTypeOther, proto.NetSurveyDevice{Model: "stale"}, now.Add(-time.Hour)),
		// By address when the survey has no MAC.
		dev("ip:10.40.7.40", "", "10.40.7.40", devTypePLC, proto.NetSurveyDevice{Model: "PLC-200"}, now),
		// Same address, different MAC: a different device, added.
		dev("aa:aa:aa:aa:aa:aa", "aa:aa:aa:aa:aa:aa", "10.40.7.30", devTypeSwitch, proto.NetSurveyDevice{}, now),
		// Only the survey found it; it is one of our own endpoints.
		dev("ip:10.40.7.99", "", "10.40.7.99", devTypeHost, proto.NetSurveyDevice{Vendor: "Acme"}, now),
	}
	out := mergeSurveyDevices(hosts, devs, map[string]string{testAgent: "line3-hmi", "agt-x": "plc-gw"}, map[string]string{"10.40.7.99": "agt-x"})
	if len(out) != 5 {
		t.Fatalf("%d hosts", len(out))
	}
	if out[0].Survey == nil || out[0].Survey.Model != "HL-L2350DW" || out[0].DeviceType != devTypePrinter || out[0].Vendor != "Brother" || out[0].Survey.SurveyedBy != "line3-hmi" {
		t.Fatalf("by MAC: %+v", out[0])
	}
	if out[1].Survey != nil {
		t.Fatalf("a different MAC at the same address was merged: %+v", out[1])
	}
	if out[2].Survey == nil || out[2].DeviceType != devTypePLC {
		t.Fatalf("by address: %+v", out[2])
	}
	added := map[string]discoveredHost{}
	for _, h := range out[3:] {
		added[h.IP+"/"+h.MAC] = h
	}
	if h := added["10.40.7.30/aa:aa:aa:aa:aa:aa"]; !h.Surveyed || h.DeviceType != devTypeSwitch || !slices.Equal(h.SeenBy, []string{"line3-hmi"}) {
		t.Fatalf("added: %+v", h)
	}
	if h := added["10.40.7.99/"]; !h.Managed || h.Hostname != "plc-gw" || h.Vendor != "Acme" {
		t.Fatalf("managed survey-only device: %+v", h)
	}
}

// Defining or running a survey takes deploy.manage and passes the
// endpoint-action gate; reading surveys does not.
func TestNetSurveyRoutePermissions(t *testing.T) {
	s := gatedServer(t)
	byPattern := map[string]*permGuard{}
	for _, e := range s.routeLog.entries {
		if pg, ok := e.Handler.(*permGuard); ok {
			byPattern[e.Pattern] = pg
		}
	}
	for _, p := range []string{"POST /api/discover/surveys", "PUT /api/discover/surveys/{id}", "DELETE /api/discover/surveys/{id}", "POST /api/discover/surveys/{id}/run"} {
		pg := byPattern[p]
		if pg == nil || !slices.Equal(pg.perms, []string{auth.PermDeployManage}) {
			t.Errorf("%s: %+v, want deploy.manage", p, pg)
		}
	}
	if pg := byPattern["GET /api/discover/surveys"]; pg == nil || !slices.Equal(pg.perms, []string{auth.PermFleetRead}) {
		t.Errorf("GET surveys: %+v", pg)
	}
	// Saving a survey on an endpoint outside the deploy action group is
	// refused before the handler runs, even for an administrator.
	admin := &store.User{ID: "usr-1", Username: "root", IsAdmin: true, Active: true}
	body := `{"name":"x","agent_ids":["agt-dc"],"subnets":["10.0.0.0/24"],"protocols":["ipp"]}`
	rec := serveGated(s, "POST /api/discover/surveys", "POST", "/api/discover/surveys", body, admin, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "action group") {
		t.Fatalf("save outside the action group: %d %q", rec.Code, rec.Body.String())
	}
	rec = serveGated(s, "POST /api/discover/surveys", "POST", "/api/discover/surveys", `{"name":"x"}`, admin, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("save with no endpoints: %d %q", rec.Code, rec.Body.String())
	}
}
