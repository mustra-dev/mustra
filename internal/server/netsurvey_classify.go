package server

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Device types Discover filters by. Decided here rather than on the
// endpoint so the rules can improve without an agent update.
const (
	devTypePrinter    = "printer"
	devTypeSwitch     = "switch"
	devTypeRouter     = "router"
	devTypeFirewall   = "firewall"
	devTypeAP         = "access-point"
	devTypePLC        = "plc"
	devTypeHMI        = "hmi"
	devTypeDrive      = "drive"
	devTypeIO         = "io-device"
	devTypeBuilding   = "building-controller"
	devTypeUPS        = "ups"
	devTypeNAS        = "nas"
	devTypeCamera     = "camera"
	devTypeHost       = "host"
	devTypeIndustrial = "industrial"
	devTypeOther      = "other"
)

// classifyDevice names what kind of device a survey found, from what it
// said about itself. Industrial and building protocols decide first: a
// PLC that also answers SNMP is a PLC. Then printers (an IPP answer or
// Printer-MIB supplies are unambiguous), then SNMP's description,
// vendor and sysServices.
func classifyDevice(d proto.NetSurveyDevice) string {
	has := func(p string) bool {
		for _, x := range d.Protocols {
			if x == p {
				return true
			}
		}
		return false
	}
	text := strings.ToLower(d.Description + " " + d.Model + " " + d.Name)
	anyOf := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has(proto.NetSurveyENIP):
		switch d.DeviceTypeCode {
		case 0x0E:
			return devTypePLC
		case 0x18:
			return devTypeHMI
		case 0x02, 0x13:
			return devTypeDrive
		case 0x07, 0x0C:
			return devTypeIO
		case 0x2C:
			return devTypeSwitch
		}
		return devTypeIndustrial
	case has(proto.NetSurveyProfinet):
		if strings.Contains(d.DeviceRole, "io-controller") {
			return devTypePLC
		}
		return devTypeIO
	case has(proto.NetSurveyBACnet):
		return devTypeBuilding
	case has(proto.NetSurveyModbus):
		if anyOf("plc", "controller", "cpu") {
			return devTypePLC
		}
		return devTypeIndustrial
	case has(proto.NetSurveyIPP), len(d.Supplies) > 0, d.PrinterState != "",
		anyOf("printer", "laserjet", "officejet", "deskjet", "imagerunner", "workcentre", "bizhub", "ecosys"):
		return devTypePrinter
	}
	vendor := strings.ToLower(d.Vendor)
	switch {
	case anyOf("firewall", "fortigate", "pan-os", "asa ", "pfsense", "opnsense") ||
		vendor == "fortinet" || vendor == "palo alto networks":
		return devTypeFirewall
	case anyOf("access point", "wireless", "wlan", "unifi ap", " ap "):
		return devTypeAP
	case anyOf("ups", "smart-ups", "powerware", "uninterruptible") || vendor == "apc":
		return devTypeUPS
	case anyOf("camera", "nvr", "axis ", "hikvision"):
		return devTypeCamera
	case anyOf("nas", "diskstation", "synology", "qnap", "truenas") || vendor == "synology" || vendor == "qnap":
		return devTypeNAS
	case anyOf("switch", "catalyst", "procurve", "arubaos-cx", "edgeswitch"):
		return devTypeSwitch
	case anyOf("router", "routeros", "edgerouter", "ios xr", "junos"):
		return devTypeRouter
	// sysServices: bit 3 (4) internet/routing, bit 2 (2) datalink/bridging.
	case d.Services&4 != 0 && d.Services&64 == 0:
		return devTypeRouter
	case d.Services&2 != 0 && d.Services&64 == 0:
		return devTypeSwitch
	case anyOf("linux", "windows", "freebsd", "darwin") || d.Services&64 != 0:
		return devTypeHost
	}
	return devTypeOther
}

// surveyDeviceKey is how a device is remembered: by MAC when one is known,
// otherwise by address until the MAC is learned.
func surveyDeviceKey(d proto.NetSurveyDevice) string {
	if d.MAC != "" {
		return d.MAC
	}
	return "ip:" + d.IP
}

// surveyReportOutcome decides a run's status from its report and which
// devices to keep. Every device must lie inside the subnets the run was
// sent with: the endpoint scopes its probes, and the server does not take
// its word for it. Devices with no address (Profinet on layer 2) need a MAC.
func surveyReportOutcome(run store.NetworkSurveyRun, rep proto.NetSurveyReport) (status, detail string, keep []proto.NetSurveyDevice, dropped int) {
	var prefixes []netip.Prefix
	for _, s := range run.Subnets {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	inScope := func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		for _, p := range prefixes {
			if p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, d := range rep.Devices {
		d.MAC = strings.ToLower(strings.TrimSpace(d.MAC))
		if _, err := netip.ParseAddr(d.IP); d.IP != "" && err != nil {
			dropped++
			continue
		}
		if (d.IP != "" && !inScope(d.IP)) || (d.IP == "" && d.MAC == "") {
			dropped++
			continue
		}
		k := surveyDeviceKey(d)
		if seen[k] || len(keep) >= 2048 {
			dropped++
			continue
		}
		seen[k] = true
		keep = append(keep, d)
	}

	var notes []string
	if len(rep.Refused) > 0 {
		var s []string
		for _, r := range rep.Refused {
			s = append(s, r.Subnet+" ("+r.Reason+")")
		}
		notes = append(notes, "refused "+strings.Join(s, ", "))
	}
	for _, u := range rep.Unsupported {
		notes = append(notes, u.Protocol+" not run: "+u.Reason)
	}
	if dropped > 0 {
		notes = append(notes, itoaInt(dropped)+" answer(s) outside the survey's subnets were discarded")
	}
	switch {
	case rep.Error != "" && len(rep.Refused) > 0 && rep.HostsPlanned == 0:
		status = "refused"
		notes = append([]string{rep.Error}, notes...)
	case rep.Error != "" && len(keep) == 0:
		status = "failed"
		notes = append([]string{rep.Error}, notes...)
	case rep.Cancelled:
		status = "cancelled"
	case rep.TimedOut:
		status = "timed_out"
		notes = append([]string{"the run's time budget ended it; what it found so far is kept"}, notes...)
	default:
		status = "succeeded"
	}
	return status, safeTruncate(strings.Join(notes, "; "), 2000), keep, dropped
}

// discoveredSurvey is what surveys learned about a Discover device.
type discoveredSurvey struct {
	proto.NetSurveyDevice
	// SurveyedBy is the hostname of the endpoint whose survey last saw it.
	SurveyedBy   string    `json:"surveyed_by"`
	SurveyedByID string    `json:"surveyed_by_id"`
	SurveyID     string    `json:"survey_id"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// mergeSurveyDevices folds survey results into Discover's device list:
// by MAC first, then by address for a device whose MAC the survey did not
// learn. A device no neighbour table lists is added, marked as surveyed.
func mergeSurveyDevices(hosts []discoveredHost, devs []store.NetworkSurveyDevice, hostnames, managedByIP map[string]string) []discoveredHost {
	byMAC := map[string]int{}
	byIP := map[string]int{}
	for i, h := range hosts {
		if h.MAC != "" {
			byMAC[strings.ToLower(h.MAC)] = i
		}
		if h.IP != "" {
			if _, dup := byIP[h.IP]; !dup || !h.Absent {
				byIP[h.IP] = i
			}
		}
	}
	// Newest first, so a device two surveys saw takes the latest answer.
	sort.SliceStable(devs, func(i, j int) bool { return devs[i].LastSeen.After(devs[j].LastSeen) })
	for _, sd := range devs {
		var d proto.NetSurveyDevice
		if json.Unmarshal(sd.Device, &d) != nil {
			continue
		}
		info := &discoveredSurvey{NetSurveyDevice: d, SurveyedBy: firstNonEmpty(hostnames[sd.AgentID], sd.AgentID), SurveyedByID: sd.AgentID,
			SurveyID: sd.SurveyID, FirstSeen: sd.FirstSeen, LastSeen: sd.LastSeen}
		idx, ok := -1, false
		if sd.MAC != "" {
			idx, ok = byMAC[sd.MAC]
		}
		if !ok && sd.IP != "" {
			if i, found := byIP[sd.IP]; found && (hosts[i].MAC == "" || sd.MAC == "" || strings.EqualFold(hosts[i].MAC, sd.MAC)) {
				idx, ok = i, true
			}
		}
		if ok {
			if hosts[idx].Survey != nil {
				continue // a newer survey answer is already attached
			}
			hosts[idx].Survey = info
			hosts[idx].DeviceType = sd.DeviceType
			if hosts[idx].Vendor == "" || hosts[idx].Vendor == "randomized MAC" {
				hosts[idx].Vendor = d.Vendor
			}
			continue
		}
		h := discoveredHost{IP: sd.IP, MAC: sd.MAC, Vendor: firstNonEmpty(d.Vendor, vendorForMAC(sd.MAC)),
			Subnet: subnetOf(sd.IP), LastSeen: sd.LastSeen, Surveyed: true, Survey: info, DeviceType: sd.DeviceType}
		h.SeenBy = appendUnique(nil, info.SurveyedBy)
		h.SeenCount = len(h.SeenBy)
		if agentID, managed := managedByIP[sd.IP]; managed && sd.IP != "" {
			h.Managed, h.AgentID, h.Hostname = true, agentID, hostnames[agentID]
		}
		hosts = append(hosts, h)
		if sd.MAC != "" {
			byMAC[sd.MAC] = len(hosts) - 1
		}
		if sd.IP != "" {
			byIP[sd.IP] = len(hosts) - 1
		}
	}
	return hosts
}
