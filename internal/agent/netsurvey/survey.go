package netsurvey

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Limits the endpoint applies whatever the job says: the server validates
// the same ranges, and an older or tampered job is clamped here.
const (
	MaxPacketsPerSecond = proto.NetSurveyMaxPacketsPerSecond
	MaxConcurrency      = proto.NetSurveyMaxConcurrency
	MinTimeout          = 200 * time.Millisecond
	MaxTimeout          = 10 * time.Second
	MaxBudget           = time.Hour
	DefaultBudget       = 15 * time.Minute
	MaxDevices          = 2048
)

// Env is what a run needs from the endpoint; tests replace it.
type Env struct {
	// Networks lists the endpoint's own IPv4 networks.
	Networks func() ([]LocalNet, error)
	// Neighbors returns the endpoint's ARP table (IP to MAC) after the
	// probes, which fills in MACs for devices that answered over IP.
	Neighbors func(ctx context.Context) map[string]string
}

// Normalize clamps a job's limits into the ranges above.
func Normalize(job *proto.NetSurveyJob) {
	job.PacketsPerSecond = clamp(job.PacketsPerSecond, 1, MaxPacketsPerSecond, 20)
	job.Concurrency = clamp(job.Concurrency, 1, MaxConcurrency, 8)
	job.TimeoutMillis = clamp(job.TimeoutMillis, int(MinTimeout/time.Millisecond), int(MaxTimeout/time.Millisecond), 1500)
	job.BudgetSeconds = clamp(job.BudgetSeconds, 10, int(MaxBudget/time.Second), int(DefaultBudget/time.Second))
}

func clamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Run carries out one survey and reports what it found. It never returns
// early on a probe error: a host that misbehaves is counted in Errors and
// the run moves on. Cancelling ctx stops it at the next probe.
func Run(ctx context.Context, job proto.NetSurveyJob, env Env) (rep proto.NetSurveyReport) {
	Normalize(&job)
	rep = proto.NetSurveyReport{RunID: job.RunID, SurveyID: job.SurveyID,
		Started: time.Now().UTC().Format(time.RFC3339), Devices: []proto.NetSurveyDevice{}}
	defer func() { rep.Finished = time.Now().UTC().Format(time.RFC3339) }()

	enabled := map[string]bool{}
	for _, p := range job.Protocols {
		enabled[p] = true
	}
	if enabled[proto.NetSurveySNMP] && job.SNMP == nil {
		rep.Unsupported = append(rep.Unsupported, proto.NetSurveyUnsupported{Protocol: proto.NetSurveySNMP, Reason: "no SNMP credential was supplied"})
		delete(enabled, proto.NetSurveySNMP)
	}
	if enabled[proto.NetSurveyProfinet] && profinetSupported != "" {
		rep.Unsupported = append(rep.Unsupported, proto.NetSurveyUnsupported{Protocol: proto.NetSurveyProfinet, Reason: profinetSupported})
		delete(enabled, proto.NetSurveyProfinet)
	}

	nets, err := env.Networks()
	if err != nil {
		rep.Error = "listing this endpoint's networks: " + err.Error()
		return rep
	}
	plan := PlanTargets(job.Subnets, nets, job.AllowOffLink)
	rep.Refused, rep.Truncated, rep.HostsPlanned = plan.Refused, plan.Truncated, len(plan.Hosts)
	if len(plan.Prefixes) == 0 {
		rep.Error = "no subnet in this survey may be surveyed from this endpoint"
		return rep
	}

	budget := time.Duration(job.BudgetSeconds) * time.Second
	rctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	lim := NewLimiter(job.PacketsPerSecond)
	timeout := time.Duration(job.TimeoutMillis) * time.Millisecond
	res := newResults(&plan)

	var bac *bacnetSession
	if enabled[proto.NetSurveyBACnet] {
		if bac, err = newBACnetSession(&plan); err != nil {
			res.note(proto.NetSurveyBACnet, err)
			bac = nil
		}
	}

	hosts := make(chan netip.Addr)
	var wg sync.WaitGroup
	for i := 0; i < job.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range hosts {
				probeHost(rctx, lim, job, enabled, bac, addr, timeout, res)
			}
		}()
	}
feed:
	for _, h := range plan.Hosts {
		select {
		case <-rctx.Done():
			break feed
		case hosts <- h:
		}
	}
	close(hosts)
	wg.Wait()

	// The broadcast and layer 2 probes go once per attached network.
	if bac != nil {
		for _, l := range plan.OnLink {
			if rctx.Err() != nil {
				break
			}
			_ = bac.whoIs(rctx, lim, l.Broadcast(), true)
		}
		for _, d := range bac.finish(rctx, timeout) {
			res.add(d)
		}
		if bac.errs > 0 {
			res.note(proto.NetSurveyBACnet, errors.New("some Who-Is requests could not be sent"))
		}
	}
	if enabled[proto.NetSurveyProfinet] {
		done := map[string]bool{}
		for _, l := range plan.OnLink {
			if rctx.Err() != nil || done[l.Interface] {
				continue
			}
			done[l.Interface] = true
			found, err := profinetIdentify(rctx, lim, l.Interface, timeout+time.Second)
			if err != nil && rctx.Err() == nil {
				res.note(proto.NetSurveyProfinet, err)
			}
			for _, d := range found {
				pd := d.device()
				// Layer 2 reaches the whole segment; keep only devices in
				// scope, or with no address yet (they are on this segment).
				if pd.IP != "" {
					if a, err := netip.ParseAddr(pd.IP); err != nil || !plan.InScope(a) {
						continue
					}
				}
				res.add(pd)
			}
		}
	}

	switch {
	case ctx.Err() != nil:
		rep.Cancelled = true
	case rctx.Err() != nil:
		rep.TimedOut = true
	}
	rep.Probes = lim.Sent()
	rep.Errors = res.notes()
	rep.Devices = res.devices()
	if env.Neighbors != nil {
		nctx, ncancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		arp := env.Neighbors(nctx)
		ncancel()
		for i := range rep.Devices {
			if rep.Devices[i].MAC == "" {
				rep.Devices[i].MAC = arp[rep.Devices[i].IP]
			}
		}
	}
	if len(rep.Devices) > MaxDevices {
		rep.Devices = rep.Devices[:MaxDevices]
		rep.Truncated = true
	}
	return rep
}

// probeHost runs every unicast probe the job enables against one host.
func probeHost(ctx context.Context, lim *Limiter, job proto.NetSurveyJob, enabled map[string]bool, bac *bacnetSession, addr netip.Addr, timeout time.Duration, res *results) {
	if !res.plan.InScope(addr) {
		return // never reached: PlanTargets built the list; kept as the last word
	}
	type probe struct {
		name string
		run  func() (*proto.NetSurveyDevice, error)
	}
	probes := []probe{
		{proto.NetSurveySNMP, func() (*proto.NetSurveyDevice, error) { return probeSNMP(ctx, lim, *job.SNMP, addr, timeout) }},
		{proto.NetSurveyIPP, func() (*proto.NetSurveyDevice, error) { return probeIPP(ctx, lim, addr, timeout) }},
		{proto.NetSurveyModbus, func() (*proto.NetSurveyDevice, error) { return probeModbus(ctx, lim, addr, timeout) }},
		{proto.NetSurveyENIP, func() (*proto.NetSurveyDevice, error) { return probeENIP(ctx, lim, addr, timeout) }},
	}
	for _, p := range probes {
		if !enabled[p.name] || ctx.Err() != nil {
			continue
		}
		d, err := p.run()
		if err != nil {
			if ctx.Err() == nil {
				res.note(p.name, err)
			}
			continue
		}
		if d != nil {
			res.add(*d)
		}
	}
	if bac != nil && ctx.Err() == nil {
		_ = bac.whoIs(ctx, lim, addr, false)
	}
}

// results merges what each protocol found about the same address.
type results struct {
	plan *Plan
	mu   sync.Mutex
	byIP map[string]*proto.NetSurveyDevice
	byL2 []proto.NetSurveyDevice // layer 2 answers with no IP
	errs map[string]*proto.NetSurveyProtocolNote
}

func newResults(plan *Plan) *results {
	return &results{plan: plan, byIP: map[string]*proto.NetSurveyDevice{}, errs: map[string]*proto.NetSurveyProtocolNote{}}
}

func (r *results) note(protocol string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.errs[protocol]
	if !ok {
		n = &proto.NetSurveyProtocolNote{Protocol: protocol, Example: truncate(err.Error(), 300)}
		r.errs[protocol] = n
	}
	n.Count++
}

func (r *results) notes() []proto.NetSurveyProtocolNote {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]proto.NetSurveyProtocolNote, 0, len(r.errs))
	for _, n := range r.errs {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Protocol < out[j].Protocol })
	return out
}

func (r *results) add(d proto.NetSurveyDevice) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d.IP == "" {
		r.byL2 = append(r.byL2, d)
		return
	}
	cur, ok := r.byIP[d.IP]
	if !ok {
		c := d
		r.byIP[d.IP] = &c
		return
	}
	MergeDevice(cur, d)
}

func (r *results) devices() []proto.NetSurveyDevice {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]proto.NetSurveyDevice, 0, len(r.byIP)+len(r.byL2))
	for _, d := range r.byIP {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return append(out, r.byL2...)
}

// MergeDevice folds what another protocol said about the same device into
// cur. The first protocol to fill a field keeps it, in probe order (SNMP,
// IPP, Modbus, EtherNet/IP, BACnet, Profinet), except that a printer's
// IPP state and supplies replace SNMP's coarser ones.
func MergeDevice(cur *proto.NetSurveyDevice, d proto.NetSurveyDevice) {
	for _, p := range d.Protocols {
		if !contains(cur.Protocols, p) {
			cur.Protocols = append(cur.Protocols, p)
		}
	}
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&cur.MAC, d.MAC)
	fill(&cur.Name, d.Name)
	fill(&cur.Description, d.Description)
	fill(&cur.Location, d.Location)
	fill(&cur.Vendor, d.Vendor)
	fill(&cur.Model, d.Model)
	fill(&cur.Firmware, d.Firmware)
	fill(&cur.Serial, d.Serial)
	fill(&cur.ObjectID, d.ObjectID)
	fill(&cur.DeviceType, d.DeviceType)
	fill(&cur.DeviceRole, d.DeviceRole)
	if cur.UptimeSeconds == 0 {
		cur.UptimeSeconds = d.UptimeSeconds
	}
	if cur.Services == 0 {
		cur.Services = d.Services
	}
	if cur.VendorID == 0 {
		cur.VendorID = d.VendorID
	}
	if cur.ProductCode == 0 {
		cur.ProductCode = d.ProductCode
	}
	if cur.DeviceTypeCode == 0 {
		cur.DeviceTypeCode = d.DeviceTypeCode
	}
	if cur.BACnetInstance == nil {
		cur.BACnetInstance = d.BACnetInstance
	}
	if len(cur.Interfaces) == 0 {
		cur.Interfaces = d.Interfaces
	}
	if contains(d.Protocols, proto.NetSurveyIPP) {
		if d.PrinterState != "" {
			cur.PrinterState, cur.PrinterReasons = d.PrinterState, d.PrinterReasons
		}
		if len(d.Supplies) > 0 {
			cur.Supplies = d.Supplies
		}
	} else if len(cur.Supplies) == 0 {
		cur.Supplies = d.Supplies
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
