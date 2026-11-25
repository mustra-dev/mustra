package server

// An item's endpoint, as mustra already knows it: one read-only page of
// what the endpoint page, Patch, Comply, Enforce, Integrity Monitor, the
// Guide and Deploy each hold about it, cut down and linked back to each.
// Nothing is collected for it. Sensor data is shown only when the
// caller's content sets grant that sensor, as everywhere else.

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// triageContextResponse is what GET /api/triage/items/{id}/context answers.
// Endpoint is absent while the item is unattached, and every other
// section with it.
type triageContextResponse struct {
	Endpoint *triageContextEndpoint `json:"endpoint,omitempty"`
	// Restricted names the sensors left out because the caller's content
	// sets do not grant them.
	Restricted      []string                   `json:"restricted,omitempty"`
	Health          *triageContextHealth       `json:"health,omitempty"`
	Software        *triageContextSoftware     `json:"software,omitempty"`
	Patches         *triageContextPatches      `json:"patches,omitempty"`
	Vulnerabilities []store.StateCount         `json:"vulnerabilities"`
	Compliance      triageContextFindings      `json:"compliance"`
	Enforce         triageContextFindings      `json:"enforce"`
	Alerts          []store.GuideNotification  `json:"alerts"`
	Changes         triageContextChanges       `json:"changes"`
	Actions         []store.AgentAction        `json:"actions"`
	Deployments     []store.EndpointDeployment `json:"deployments"`
	// OtherItems are the endpoint's other open triage items.
	OtherItems []store.TriageItem `json:"other_items"`
}

type triageContextEndpoint struct {
	AgentID         string     `json:"agent_id"`
	Hostname        string     `json:"hostname"`
	OS              string     `json:"os"`
	Platform        string     `json:"platform"`
	PlatformVersion string     `json:"platform_version"`
	AgentVersion    string     `json:"agent_version"`
	Site            string     `json:"site"`
	IPs             []string   `json:"ips"`
	Online          bool       `json:"online"`
	Managed         bool       `json:"managed"`
	LastHeartbeat   *time.Time `json:"last_heartbeat,omitempty"`
	Manufacturer    string     `json:"manufacturer,omitempty"`
	Model           string     `json:"model,omitempty"`
	Serial          string     `json:"serial,omitempty"`
	UptimeHours     float64    `json:"uptime_hours,omitempty"`
}

// triageContextHealth is the endpoint's Performance score (see
// health.go) and the readings it is built from.
type triageContextHealth struct {
	Score       int       `json:"score"`
	Band        string    `json:"band"`
	CPUPeak     float64   `json:"cpu_peak"`
	MemoryPeak  float64   `json:"memory_peak"`
	DiskCurrent float64   `json:"disk_current"`
	WindowHours float64   `json:"window_hours"`
	CollectedAt time.Time `json:"collected_at"`
}

type triageContextSoftware struct {
	Count int `json:"count"`
	// Recent are the most recently installed, where the platform records
	// install dates.
	Recent      []proto.InstalledApp `json:"recent"`
	CollectedAt time.Time            `json:"collected_at"`
}

type triageContextPatches struct {
	Pending         int               `json:"pending"`
	Security        int               `json:"security"`
	RestartRequired int               `json:"restart_required"`
	Items           []proto.PatchInfo `json:"items"`
	CollectedAt     time.Time         `json:"collected_at"`
}

type triageContextFindings struct {
	Counts  []store.StateCount      `json:"counts"`
	Failing []store.EndpointFinding `json:"failing"`
}

type triageContextChanges struct {
	// Total counts changes in the last seven days; Recent lists the newest.
	Total  int                    `json:"total"`
	Recent []store.EndpointChange `json:"recent"`
}

const triageContextRows = 10

// triageContext assembles the page. A section whose source fails is left
// empty rather than failing the page: a broken compliance table should not
// hide the patches.
func (s *Server) triageContext(ctx context.Context, it store.TriageItem) (triageContextResponse, error) {
	out := triageContextResponse{Vulnerabilities: []store.StateCount{}, Alerts: []store.GuideNotification{},
		Actions: []store.AgentAction{}, Deployments: []store.EndpointDeployment{}, OtherItems: []store.TriageItem{},
		Compliance: triageContextFindings{Counts: []store.StateCount{}, Failing: []store.EndpointFinding{}},
		Enforce:    triageContextFindings{Counts: []store.StateCount{}, Failing: []store.EndpointFinding{}},
		Changes:    triageContextChanges{Recent: []store.EndpointChange{}}}
	if it.AgentID == "" {
		return out, nil
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return out, err
	}
	for _, a := range agents {
		if a.AgentID == it.AgentID {
			out.Endpoint = &triageContextEndpoint{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Platform: a.Platform,
				PlatformVersion: a.PlatformVersion, AgentVersion: a.AgentVersion, Site: a.Site, IPs: a.IPs, Online: a.Online,
				Managed: a.Managed, LastHeartbeat: a.LastHeartbeat}
		}
	}
	if out.Endpoint == nil {
		// Removed from inventory since; the item keeps its ID.
		return out, nil
	}
	allowed, err := s.sensorFilter(ctx)
	if err != nil {
		return out, err
	}
	warn := func(what string, err error) {
		if err != nil {
			s.logger.Warn("triage context: section left empty", "section", what, "agent", it.AgentID, "error", err)
		}
	}
	sensor := func(kind proto.SensorKind, into any) (time.Time, bool) {
		if !allowed(string(kind)) {
			out.Restricted = append(out.Restricted, string(kind))
			return time.Time{}, false
		}
		rec, err := s.store.GetSensorData(ctx, it.AgentID, string(kind))
		warn(string(kind), err)
		if rec == nil || json.Unmarshal(rec.Data, into) != nil {
			return time.Time{}, false
		}
		return rec.CollectedAt, true
	}

	var hw []proto.HardwareInfo
	if _, ok := sensor(proto.SensorHardware, &hw); ok && len(hw) > 0 {
		out.Endpoint.Manufacturer, out.Endpoint.Model, out.Endpoint.Serial = hw[0].Manufacturer, hw[0].Model, hw[0].Serial
		out.Endpoint.UptimeHours = hw[0].UptimeHours
	}
	var perf []proto.PerformanceInfo
	if at, ok := sensor(proto.SensorPerformance, &perf); ok && len(perf) > 0 && perf[0].Samples > 0 {
		score, b := healthOf(perf[0])
		out.Health = &triageContextHealth{Score: score, Band: b, CPUPeak: perf[0].CPUPeak, MemoryPeak: perf[0].MemoryPeak,
			DiskCurrent: perf[0].DiskCurrent, WindowHours: perf[0].WindowHours, CollectedAt: at}
	}
	var apps []proto.InstalledApp
	if at, ok := sensor(proto.SensorInstalledApps, &apps); ok {
		sw := &triageContextSoftware{Count: len(apps), CollectedAt: at, Recent: []proto.InstalledApp{}}
		dated := make([]proto.InstalledApp, 0, len(apps))
		for _, a := range apps {
			if a.InstallDate != "" {
				dated = append(dated, a)
			}
		}
		sort.SliceStable(dated, func(i, j int) bool { return dated[i].InstallDate > dated[j].InstallDate })
		if len(dated) > triageContextRows {
			dated = dated[:triageContextRows]
		}
		sw.Recent = append(sw.Recent, dated...)
		out.Software = sw
	}
	var patches []proto.PatchInfo
	if at, ok := sensor(proto.SensorPatches, &patches); ok {
		p := &triageContextPatches{Pending: len(patches), CollectedAt: at, Items: []proto.PatchInfo{}}
		for _, pi := range patches {
			if pi.Severity == "security" {
				p.Security++
			}
			if pi.RestartRequired {
				p.RestartRequired++
			}
		}
		sort.SliceStable(patches, func(i, j int) bool { return patches[i].Severity == "security" && patches[j].Severity != "security" })
		if len(patches) > triageContextRows {
			patches = patches[:triageContextRows]
		}
		p.Items = append(p.Items, patches...)
		out.Patches = p
	}

	if v, err := s.store.EndpointVulnerabilityCounts(ctx, it.AgentID); err == nil {
		out.Vulnerabilities = v
	} else {
		warn("vulnerabilities", err)
	}
	if c, f, err := s.store.EndpointComplianceSummary(ctx, it.AgentID, triageContextRows); err == nil {
		out.Compliance = triageContextFindings{Counts: c, Failing: f}
	} else {
		warn("compliance", err)
	}
	if c, f, err := s.store.EndpointEnforceSummary(ctx, it.AgentID, triageContextRows); err == nil {
		out.Enforce = triageContextFindings{Counts: c, Failing: f}
	} else {
		warn("enforce", err)
	}
	if a, err := s.store.OpenGuideForEndpoint(ctx, it.AgentID); err == nil {
		out.Alerts = a
	} else {
		warn("alerts", err)
	}
	if c, n, err := s.store.RecentEndpointChanges(ctx, it.AgentID, time.Now().Add(-7*24*time.Hour), triageContextRows); err == nil {
		out.Changes = triageContextChanges{Total: n, Recent: c}
	} else {
		warn("changes", err)
	}
	if a, err := s.store.ListAgentActions(ctx, it.AgentID, triageContextRows); err == nil && a != nil {
		out.Actions = a
	} else {
		warn("actions", err)
	}
	if d, err := s.store.RecentEndpointDeployments(ctx, it.AgentID, triageContextRows); err == nil {
		out.Deployments = d
	} else {
		warn("deployments", err)
	}
	if others, err := s.store.ListTriageItems(ctx, store.TriageFilter{AgentID: it.AgentID, Open: true, Limit: 20}); err == nil {
		for _, o := range others {
			if o.ID != it.ID {
				out.OtherItems = append(out.OtherItems, o)
			}
		}
	} else {
		warn("other items", err)
	}
	return out, nil
}

// healthOf is the Performance score of one endpoint's readings, for the
// Performance page and a triage item's endpoint alike. Disk is weighted
// highest: a full disk stops a machine outright, where sustained CPU
// merely makes it slow.
func healthOf(p proto.PerformanceInfo) (int, string) {
	score := int(math.Round(0.30*float64(categoryScore(p.CPUEvents)) +
		0.30*float64(categoryScore(p.MemoryEvents)) +
		0.40*float64(categoryScore(p.DiskEvents))))
	return score, band(score)
}

// handleTriageContext serves GET /api/triage/items/{id}/context.
func (s *Server) handleTriageContext(w http.ResponseWriter, r *http.Request) {
	it, err := s.store.GetTriageItem(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	out, err := s.triageContext(r.Context(), *it)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}
