// Package netsurvey runs a network survey on an endpoint: read-only
// identification probes (SNMP, IPP, Modbus TCP device identification,
// BACnet Who-Is, EtherNet/IP List Identity, Profinet DCP Identify) against
// subnets the endpoint is directly attached to.
//
// Every probe here asks a device what it is and nothing else. None of
// them writes, configures, starts, stops or resets anything, and each
// protocol file says why its request is safe on a live plant or office
// network. The run is bounded by the job: the addresses it may touch
// (Plan), how fast (Limiter), how many hosts at once, how long each
// answer may take and how long the whole run may last.
package netsurvey

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

const (
	// MinPrefixBits, MaxSubnets: see the proto limits.
	MinPrefixBits = proto.NetSurveyMinPrefixBits
	MaxSubnets    = proto.NetSurveyMaxSubnets
	// MaxHosts caps the addresses one run probes across all its subnets.
	MaxHosts = 4096
)

// Plan is the set of addresses a run may probe, decided before the first
// packet: every probe and every answer is checked against it.
type Plan struct {
	Hosts     []netip.Addr
	Refused   []proto.NetSurveyRefusal
	Truncated bool
	// Prefixes are the accepted subnets, which bound every answer too: a
	// reply from outside them (to a broadcast, say) is dropped.
	Prefixes []netip.Prefix
	// OnLink are accepted subnets that are exactly a network the endpoint
	// is attached to, and so may be reached by that network's broadcast
	// (BACnet Who-Is) or by layer 2 (Profinet DCP); with the interface.
	OnLink []LinkNet
}

// LinkNet is one directly attached network and the interface it is on.
type LinkNet struct {
	Prefix    netip.Prefix
	Interface string
}

// Broadcast returns the network's directed broadcast address.
func (l LinkNet) Broadcast() netip.Addr {
	a := l.Prefix.Masked().Addr().As4()
	bits := l.Prefix.Bits()
	for i := bits; i < 32; i++ {
		a[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(a)
}

// InScope reports whether addr lies in an accepted subnet.
func (p Plan) InScope(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, pfx := range p.Prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// LocalNet is one of the endpoint's own IPv4 networks.
type LocalNet struct {
	Prefix    netip.Prefix // address/bits as configured, e.g. 192.168.1.20/24
	Interface string
}

// LocalNetworks lists the endpoint's IPv4 networks on interfaces that are
// up and not loopback.
func LocalNetworks() ([]LocalNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []LocalNet
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			out = append(out, LocalNet{Prefix: netip.PrefixFrom(ip, ones), Interface: ifc.Name})
		}
	}
	return out, nil
}

// PlanTargets decides what a job may touch. A subnet is refused when it
// is not IPv4, is larger than /22, or (unless allowOffLink) is not inside
// a network one of local's interfaces is directly attached to. Network
// and broadcast addresses, the endpoint's own addresses, and anything
// loopback, multicast or link-local are never probed.
func PlanTargets(subnets []string, local []LocalNet, allowOffLink bool) Plan {
	var p Plan
	self := map[netip.Addr]bool{}
	for _, l := range local {
		self[l.Prefix.Addr()] = true
	}
	seen := map[netip.Addr]bool{}
	for i, raw := range subnets {
		raw = strings.TrimSpace(raw)
		if i >= MaxSubnets {
			p.Refused = append(p.Refused, proto.NetSurveyRefusal{Subnet: raw, Reason: fmt.Sprintf("more than %d subnets in one survey", MaxSubnets)})
			continue
		}
		pfx, err := parseSubnet(raw)
		if err != nil {
			p.Refused = append(p.Refused, proto.NetSurveyRefusal{Subnet: raw, Reason: err.Error()})
			continue
		}
		link, attached := attachedTo(pfx, local)
		if !attached && !allowOffLink {
			p.Refused = append(p.Refused, proto.NetSurveyRefusal{Subnet: pfx.String(),
				Reason: "not a network this endpoint is directly attached to"})
			continue
		}
		p.Prefixes = append(p.Prefixes, pfx)
		if attached && link.Prefix.Masked() == pfx {
			p.OnLink = append(p.OnLink, LinkNet{Prefix: pfx, Interface: link.Interface})
		}
		bcast := LinkNet{Prefix: pfx}.Broadcast()
		for a := pfx.Addr(); pfx.Contains(a); a = a.Next() {
			if pfx.Bits() <= 30 && (a == pfx.Addr() || a == bcast) {
				continue
			}
			if self[a] || seen[a] || !a.IsGlobalUnicast() {
				continue
			}
			if len(p.Hosts) >= MaxHosts {
				p.Truncated = true
				break
			}
			seen[a] = true
			p.Hosts = append(p.Hosts, a)
		}
	}
	sort.Slice(p.Hosts, func(i, j int) bool { return p.Hosts[i].Less(p.Hosts[j]) })
	return p
}

func parseSubnet(raw string) (netip.Prefix, error) { return proto.ParseNetSurveySubnet(raw) }

// attachedTo finds the local network that contains all of pfx.
func attachedTo(pfx netip.Prefix, local []LocalNet) (LocalNet, bool) {
	for _, l := range local {
		ln := l.Prefix.Masked()
		if ln.Bits() <= pfx.Bits() && ln.Contains(pfx.Addr()) {
			return l, true
		}
	}
	return LocalNet{}, false
}
