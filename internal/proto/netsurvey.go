package proto

import (
	"fmt"
	"net/netip"
	"strings"
)

// Network surveys: an opt-in, read-only identification pass an operator
// asks chosen endpoints to run against subnets they sit on. Discover
// itself never sends a packet (it reads neighbour tables); a survey does,
// so everything about it is bounded by the job: which subnets, which
// protocols, how fast, how long. See docs/CONCEPTS.md, "Network surveys".

// Survey protocol names, as they appear in a job and in a device's
// Protocols list.
const (
	NetSurveySNMP     = "snmp"
	NetSurveyIPP      = "ipp"
	NetSurveyModbus   = "modbus"
	NetSurveyBACnet   = "bacnet"
	NetSurveyProfinet = "profinet"
	NetSurveyENIP     = "enip"
)

// NetSurveyProtocols is every protocol a survey may use, in the order the
// console lists them.
var NetSurveyProtocols = []string{NetSurveySNMP, NetSurveyIPP, NetSurveyModbus, NetSurveyBACnet, NetSurveyENIP, NetSurveyProfinet}

// NetSurveyJob is the network_survey command: one run on one endpoint.
// It travels on the request/reply command subject, which is not kept in
// any stream, so the SNMP secrets it carries exist on the endpoint only
// for the run.
type NetSurveyJob struct {
	RunID    string `json:"run_id"`
	SurveyID string `json:"survey_id"`
	Name     string `json:"name,omitempty"`
	// Subnets are IPv4 CIDRs. Each must be a network this endpoint is
	// directly attached to unless AllowOffLink is set; the endpoint checks
	// this itself against its own interfaces and refuses the rest.
	Subnets      []string `json:"subnets"`
	AllowOffLink bool     `json:"allow_off_link,omitempty"`
	Protocols    []string `json:"protocols"`
	// PacketsPerSecond caps every probe packet and connection attempt the
	// run makes, across all protocols; Concurrency caps hosts in flight.
	PacketsPerSecond int `json:"packets_per_second"`
	Concurrency      int `json:"concurrency"`
	// TimeoutMillis is how long one probe waits for its answer.
	TimeoutMillis int `json:"timeout_ms"`
	// BudgetSeconds ends the whole run, finished or not.
	BudgetSeconds int            `json:"budget_seconds"`
	SNMP          *NetSurveyCred `json:"snmp,omitempty"`
}

// NetSurveyCred is SNMP access for one run. Never logged, never stored on
// the endpoint, never echoed in a report.
type NetSurveyCred struct {
	Version   string `json:"version"` // "2c" or "3"
	Community string `json:"community,omitempty"`
	// SNMPv3 (USM).
	User           string `json:"user,omitempty"`
	SecurityLevel  string `json:"security_level,omitempty"` // noAuthNoPriv | authNoPriv | authPriv
	AuthProtocol   string `json:"auth_protocol,omitempty"`  // MD5 SHA SHA224 SHA256 SHA384 SHA512
	AuthPassphrase string `json:"auth_passphrase,omitempty"`
	PrivProtocol   string `json:"priv_protocol,omitempty"` // DES AES AES192 AES256 AES192C AES256C
	PrivPassphrase string `json:"priv_passphrase,omitempty"`
}

// String keeps the secrets out of anything that formats the value.
func (c NetSurveyCred) String() string {
	return "snmp v" + c.Version + " (credentials redacted)"
}

// SensorNetSurvey is the snapshot kind a survey report travels on. Like
// Reveal's, it is not a periodic sensor: it uses the durable snapshot
// path and the broker permission every snapshot already has.
const SensorNetSurvey SensorKind = "netsurvey"

// NetSurveyReport is what one run found, published once when it ends.
type NetSurveyReport struct {
	RunID    string `json:"run_id"`
	SurveyID string `json:"survey_id"`
	AgentID  string `json:"agent_id"`
	Started  string `json:"started"`
	Finished string `json:"finished"`
	// HostsPlanned is the addresses the run set out to probe after
	// scoping; Probes the packets and connection attempts it made.
	HostsPlanned int                     `json:"hosts_planned"`
	Probes       int                     `json:"probes"`
	Refused      []NetSurveyRefusal      `json:"refused,omitempty"`
	Unsupported  []NetSurveyUnsupported  `json:"unsupported,omitempty"`
	Truncated    bool                    `json:"truncated,omitempty"`
	TimedOut     bool                    `json:"timed_out,omitempty"`
	Cancelled    bool                    `json:"cancelled,omitempty"`
	Error        string                  `json:"error,omitempty"`
	Devices      []NetSurveyDevice       `json:"devices"`
	Errors       []NetSurveyProtocolNote `json:"errors,omitempty"`
}

// NetSurveyRefusal is a subnet the endpoint would not survey, and why.
type NetSurveyRefusal struct {
	Subnet string `json:"subnet"`
	Reason string `json:"reason"`
}

// NetSurveyUnsupported is a protocol this endpoint cannot run (Profinet
// DCP off Linux, say).
type NetSurveyUnsupported struct {
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
}

// NetSurveyProtocolNote counts what went wrong with one protocol across
// the run, rather than one line per host.
type NetSurveyProtocolNote struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
	Example  string `json:"example"`
}

// NetSurveyDevice is one device that answered at least one probe.
type NetSurveyDevice struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	Protocols []string `json:"protocols"`

	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Location    string `json:"location,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Model       string `json:"model,omitempty"`
	Firmware    string `json:"firmware,omitempty"`
	Serial      string `json:"serial,omitempty"`

	// SNMP system group.
	ObjectID      string `json:"object_id,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	// Services is sysServices: bit 1 (2) a bridge/switch, bit 2 (4) a
	// router, bit 6 (64) an application host. 0 when not reported.
	Services   int                  `json:"services,omitempty"`
	Interfaces []NetSurveyInterface `json:"interfaces,omitempty"`

	// Printers (Printer-MIB, IPP).
	PrinterState   string            `json:"printer_state,omitempty"`
	PrinterReasons []string          `json:"printer_reasons,omitempty"`
	Supplies       []NetSurveySupply `json:"supplies,omitempty"`

	// Industrial identity: what the device says it is.
	VendorID       int    `json:"vendor_id,omitempty"`
	ProductCode    int    `json:"product_code,omitempty"`
	DeviceTypeCode int    `json:"device_type_code,omitempty"`
	DeviceType     string `json:"device_type,omitempty"` // as the protocol names it
	DeviceRole     string `json:"device_role,omitempty"` // Profinet: io-device, io-controller…
	// BACnetInstance is the device object's instance number; -1 or absent
	// when there is none.
	BACnetInstance *int `json:"bacnet_instance,omitempty"`
}

// NetSurveyInterface is one ifTable row.
type NetSurveyInterface struct {
	Name   string `json:"name"`
	MAC    string `json:"mac,omitempty"`
	Status string `json:"status,omitempty"` // up | down | testing | unknown …
}

// NetSurveySupply is one printer supply (toner, drum, waste…).
type NetSurveySupply struct {
	Name string `json:"name"`
	// Percent is 0-100, or -1 when the device does not say how much is
	// left (Printer-MIB "unknown" or "some remaining").
	Percent int    `json:"percent"`
	Color   string `json:"color,omitempty"`
}

// Limits a survey may not exceed. The server refuses a survey outside
// them and the endpoint clamps a job to them, so neither trusts the other.
const (
	// NetSurveyMinPrefixBits is the largest subnet one entry may name: /22,
	// 1024 addresses. A survey is for the segments an endpoint sits on,
	// not for sweeping a /8.
	NetSurveyMinPrefixBits = 22
	// NetSurveyMaxSubnets caps the entries in one survey.
	NetSurveyMaxSubnets = 16
	// NetSurveyMaxPacketsPerSecond and NetSurveyMaxConcurrency cap a run's
	// rate and the hosts it probes at once.
	NetSurveyMaxPacketsPerSecond = 200
	NetSurveyMaxConcurrency      = 32
)

// ParseNetSurveySubnet validates one survey subnet: an IPv4 unicast CIDR
// no larger than /22. A bare address is a /32. It returns the network.
func ParseNetSurveySubnet(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty subnet")
	}
	var pfx netip.Prefix
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not a CIDR subnet")
		}
		pfx = p
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not a CIDR subnet")
		}
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("only IPv4 subnets can be surveyed")
	}
	if pfx.Bits() < NetSurveyMinPrefixBits {
		return netip.Prefix{}, fmt.Errorf("larger than /%d", NetSurveyMinPrefixBits)
	}
	a := pfx.Addr()
	if a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return netip.Prefix{}, fmt.Errorf("not a unicast network")
	}
	return pfx.Masked(), nil
}
