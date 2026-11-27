package netsurvey

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func local(cidrs ...string) []LocalNet {
	var out []LocalNet
	for _, c := range cidrs {
		out = append(out, LocalNet{Prefix: netip.MustParsePrefix(c), Interface: "eth0"})
	}
	return out
}

func TestPlanRefusesOutOfScopeSubnets(t *testing.T) {
	nets := local("192.168.10.20/24", "10.4.0.7/16")
	p := PlanTargets([]string{
		"192.168.10.0/24",   // the attached network: accepted, on-link
		"10.4.8.0/23",       // inside an attached /16: accepted, not on-link
		"192.168.11.0/24",   // a different network: refused
		"10.4.0.0/16",       // larger than /22: refused
		"2001:db8::/120",    // IPv6: refused
		"127.0.0.0/24",      // loopback: refused
		"224.0.0.0/24",      // multicast: refused
		"not-a-subnet",      // refused
		"192.168.10.200/32", // a single host, already covered: accepted
	}, nets, false)
	if len(p.Prefixes) != 3 {
		t.Fatalf("accepted %v", p.Prefixes)
	}
	refused := map[string]string{}
	for _, r := range p.Refused {
		refused[r.Subnet] = r.Reason
	}
	for _, s := range []string{"192.168.11.0/24", "10.4.0.0/16", "2001:db8::/120", "127.0.0.0/24", "224.0.0.0/24", "not-a-subnet"} {
		if refused[s] == "" {
			t.Errorf("%s was not refused (%v)", s, refused)
		}
	}
	if !strings.Contains(refused["192.168.11.0/24"], "directly attached") {
		t.Errorf("off-link reason: %q", refused["192.168.11.0/24"])
	}
	if len(p.OnLink) != 1 || p.OnLink[0].Prefix.String() != "192.168.10.0/24" || p.OnLink[0].Broadcast().String() != "192.168.10.255" {
		t.Errorf("on-link: %+v", p.OnLink)
	}
	// 254 usable in the /24 minus the endpoint itself, plus 510 in the /23.
	if len(p.Hosts) != 253+510 {
		t.Errorf("hosts: %d", len(p.Hosts))
	}
	for _, h := range p.Hosts {
		if !p.InScope(h) {
			t.Fatalf("%s planned but out of scope", h)
		}
		switch h.String() {
		case "192.168.10.0", "192.168.10.255", "192.168.10.20", "10.4.8.0", "10.4.9.255":
			t.Errorf("planned %s (network, broadcast or self)", h)
		}
	}
	for _, out := range []string{"192.168.11.5", "10.4.10.1", "8.8.8.8"} {
		if p.InScope(netip.MustParseAddr(out)) {
			t.Errorf("%s is in scope", out)
		}
	}

	// Off-link allowed explicitly: accepted, but never on-link (no
	// broadcast, no layer 2).
	p = PlanTargets([]string{"192.168.11.0/24"}, nets, true)
	if len(p.Prefixes) != 1 || len(p.OnLink) != 0 || len(p.Hosts) != 254 {
		t.Errorf("allow off-link: %+v", p)
	}
}

func TestPlanCapsHosts(t *testing.T) {
	var subnets []string
	for i := 0; i < 6; i++ {
		subnets = append(subnets, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 9, byte(i * 4), 0}), 22).String())
	}
	p := PlanTargets(subnets, local("10.9.0.1/16"), false)
	if len(p.Hosts) != MaxHosts || !p.Truncated {
		t.Fatalf("hosts %d truncated %v", len(p.Hosts), p.Truncated)
	}
	many := make([]string, MaxSubnets+2)
	for i := range many {
		many[i] = "10.9.0.1/32"
	}
	if p := PlanTargets(many, local("10.9.0.1/16"), false); len(p.Refused) != 2 {
		t.Fatalf("refused %d", len(p.Refused))
	}
}

func TestLimiterSpacesProbes(t *testing.T) {
	lim := NewLimiter(50) // 20 ms apart
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // concurrent callers share the one budget
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if err := lim.Wait(context.Background()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	// 24 probes at 50/s: the last may go no sooner than 23 intervals in.
	if el := time.Since(start); el < 23*20*time.Millisecond {
		t.Fatalf("24 probes at 50/s took only %s", el)
	}
	if lim.Sent() != 24 {
		t.Fatalf("sent %d", lim.Sent())
	}

	slow := NewLimiter(1)
	_ = slow.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if err := slow.Wait(ctx); err == nil || time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("a cancelled wait returned %v after %s", err, time.Since(t0))
	}
	if slow.Sent() != 1 {
		t.Fatalf("a cancelled wait was counted")
	}
}

func TestNormalizeClampsLimits(t *testing.T) {
	j := proto.NetSurveyJob{PacketsPerSecond: 100000, Concurrency: -4, TimeoutMillis: 1, BudgetSeconds: 999999}
	Normalize(&j)
	if j.PacketsPerSecond != MaxPacketsPerSecond || j.Concurrency != 1 || j.TimeoutMillis != 200 || j.BudgetSeconds != 3600 {
		t.Fatalf("%+v", j)
	}
	j = proto.NetSurveyJob{}
	Normalize(&j)
	if j.PacketsPerSecond != 20 || j.Concurrency != 8 || j.TimeoutMillis != 1500 || j.BudgetSeconds != 900 {
		t.Fatalf("defaults %+v", j)
	}
}

// A run refuses what it may not touch before sending anything, and a
// cancelled run stops.
func TestRunScopingAndCancellation(t *testing.T) {
	env := Env{Networks: func() ([]LocalNet, error) { return local("192.0.2.10/24"), nil }}
	rep := Run(context.Background(), proto.NetSurveyJob{Subnets: []string{"198.51.100.0/24"}, Protocols: []string{proto.NetSurveyModbus}}, env)
	if rep.Probes != 0 || rep.Error == "" || len(rep.Refused) != 1 || rep.HostsPlanned != 0 {
		t.Fatalf("off-link run: %+v", rep)
	}

	// TEST-NET-1 is never routed: every TCP connect hangs until its
	// timeout, which is what a cancellation has to cut short.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	rep = Run(ctx, proto.NetSurveyJob{Subnets: []string{"192.0.2.0/24"}, Protocols: []string{proto.NetSurveyModbus, proto.NetSurveyProfinet},
		PacketsPerSecond: 5, Concurrency: 2, TimeoutMillis: 5000}, env)
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("a cancelled run took %s", el)
	}
	if !rep.Cancelled || rep.Probes > 5 {
		t.Fatalf("cancelled run: cancelled=%v probes=%d", rep.Cancelled, rep.Probes)
	}
	if rep.Finished == "" {
		t.Fatal("no finish time")
	}
}

func TestRunNeverCarriesCredentials(t *testing.T) {
	env := Env{Networks: func() ([]LocalNet, error) { return local("192.0.2.10/24"), nil }}
	cred := &proto.NetSurveyCred{Version: "3", User: "u", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassphrase: "s3cret-auth", PrivProtocol: "AES", PrivPassphrase: "s3cret-priv", Community: "s3cret-comm"}
	rep := Run(context.Background(), proto.NetSurveyJob{Subnets: []string{"198.51.100.0/24"}, Protocols: []string{proto.NetSurveySNMP}, SNMP: cred}, env)
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("report carries a credential: %s", raw)
	}
	if s := cred.String(); strings.Contains(s, "s3cret") {
		t.Fatalf("String() shows a credential: %s", s)
	}
}

func TestMergeDevice(t *testing.T) {
	snmp := proto.NetSurveyDevice{IP: "192.0.2.5", Protocols: []string{"snmp"}, Name: "printer-a", Vendor: "HP",
		Supplies: []proto.NetSurveySupply{{Name: "Toner", Percent: -1}}}
	ipp := proto.NetSurveyDevice{IP: "192.0.2.5", Protocols: []string{"ipp"}, Name: "Front desk", Model: "LaserJet 400",
		PrinterState: "idle", Supplies: []proto.NetSurveySupply{{Name: "Black", Percent: 40}}}
	cur := snmp
	MergeDevice(&cur, ipp)
	if cur.Name != "printer-a" || cur.Model != "LaserJet 400" || cur.PrinterState != "idle" ||
		len(cur.Supplies) != 1 || cur.Supplies[0].Percent != 40 || strings.Join(cur.Protocols, ",") != "snmp,ipp" {
		t.Fatalf("%+v", cur)
	}
	MergeDevice(&cur, ipp)
	if len(cur.Protocols) != 2 {
		t.Fatalf("protocols repeated: %v", cur.Protocols)
	}
}
