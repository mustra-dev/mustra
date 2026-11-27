package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/anomaly"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// anomalyMetricView describes one judged metric for the page.
type anomalyMetricView struct {
	Metric string `json:"metric"`
	Label  string `json:"label"`
	Unit   string `json:"unit"`
	Sensor string `json:"sensor"` // empty for the endpoint's own facts
	// Source says where the value comes from on each platform.
	Source string `json:"source"`
}

// anomalyView is one anomaly as the console shows it.
type anomalyView struct {
	store.Anomaly
	MetricLabel string `json:"metric_label"`
	Unit        string `json:"unit"`
	// Group is the fleet group this anomaly belongs to (its metric and
	// direction, "cpu-high"), as in /anomalies?group=.
	Group string `json:"group"`
	// BandLo and BandHi are the normal range at the baseline the anomaly
	// opened on.
	BandLo float64 `json:"band_lo"`
	BandHi float64 `json:"band_hi"`
	// Suppressed is set when a suppression covers this anomaly;
	// SuppressionID names it.
	Suppressed    bool   `json:"suppressed"`
	SuppressionID string `json:"suppression_id,omitempty"`
}

// anomalyGroupView is the same anomaly on several endpoints.
type anomalyGroupView struct {
	// ID is the metric and direction ("cpu-high"): stable, so a group
	// has a URL (/anomalies?group=cpu-high) whatever its members.
	ID          string `json:"id"`
	Metric      string `json:"metric"`
	MetricLabel string `json:"metric_label"`
	Direction   string `json:"direction"`
	Endpoints   int    `json:"endpoints"`
	// Active is how many are neither acknowledged nor suppressed.
	Active int `json:"active"`
	// Rank is the active members' severity scores summed: average
	// severity times endpoints affected.
	Rank     float64 `json:"rank"`
	Severity string  `json:"severity"`
	// Change is a change most of the group went through in the day
	// before, when at least two and at least half did.
	Change          string   `json:"change"`
	ChangeEndpoints int      `json:"change_endpoints"`
	AnomalyIDs      []string `json:"anomaly_ids"`
	AgentIDs        []string `json:"agent_ids"`
}

// listAnomaliesResponse is what GET /api/anomalies answers.
type listAnomaliesResponse struct {
	Groups    []anomalyGroupView  `json:"groups"`
	Anomalies []anomalyView       `json:"anomalies"`
	Metrics   []anomalyMetricView `json:"metrics"`
	// Tracked is how many endpoints have a baseline for at least one
	// metric; Learning how many of those have none ready yet.
	Tracked  int `json:"tracked"`
	Learning int `json:"learning"`
	// Suppressed is how many anomalies a suppression hides (listed only
	// with suppressed=1).
	Suppressed    int `json:"suppressed"`
	Acknowledged  int `json:"acknowledged"`
	MinHours      int `json:"min_hours"`
	SustainMins   int `json:"sustain_minutes"`
	RetentionDays int `json:"closed_retention_days"`
}

// anomalyPoint is one point of a chart.
type anomalyPoint struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// anomalyDetailResponse is what GET /api/anomalies/{id} answers: the
// anomaly, and what to draw it against.
type anomalyDetailResponse struct {
	Anomaly anomalyView `json:"anomaly"`
	// Baseline is the endpoint's current baseline for the metric, and
	// Band the normal range it gives (Ready false while learning).
	Baseline anomaly.Baseline `json:"baseline"`
	Band     anomaly.Band     `json:"band"`
	Ready    bool             `json:"ready"`
	// Samples are the last day's five-minute values; Hours the hourly
	// medians, lows and highs over the baseline window.
	Samples []anomalyPoint      `json:"samples"`
	Hours   []store.AnomalyHour `json:"hours"`
	// Others are the endpoint's other open anomalies.
	Others []anomalyView `json:"others"`
}

func anomalyMetricViews(visible func(string) bool) []anomalyMetricView {
	out := []anomalyMetricView{}
	for _, m := range anomaly.Metrics {
		if m.Sensor != "" && !visible(m.Sensor) {
			continue
		}
		out = append(out, anomalyMetricView{Metric: m.Key, Label: m.Label, Unit: m.Unit, Sensor: m.Sensor, Source: m.Source})
	}
	return out
}

// anomalyAccess is what the caller may see: endpoints inside their
// management rights, metrics from sensors their content sets grant.
type anomalyAccess struct {
	scope  map[string]bool
	sensor func(string) bool
}

func (s *Server) anomalyAccess(ctx context.Context) (anomalyAccess, error) {
	scope, err := s.endpointScope(ctx)
	if err != nil {
		return anomalyAccess{}, err
	}
	sensor, err := s.sensorFilter(ctx)
	if err != nil {
		return anomalyAccess{}, err
	}
	return anomalyAccess{scope: scope, sensor: sensor}, nil
}

func (a anomalyAccess) sees(agentID, metric string) bool {
	if a.scope != nil && !a.scope[agentID] {
		return false
	}
	m, ok := anomaly.Lookup(metric)
	return ok && (m.Sensor == "" || a.sensor(m.Sensor))
}

// anomalySuppressor says which suppression, if any, covers an anomaly.
// A suppression on a group that has since been deleted covers nothing:
// a lost group must not widen into the whole fleet.
func (s *Server) anomalySuppressor(ctx context.Context, now time.Time) (func(agentID, metric string) string, error) {
	sups, err := s.store.ListAnomalySuppressions(ctx)
	if err != nil {
		return nil, err
	}
	var live []store.AnomalySuppression
	for _, x := range sups {
		if x.ExpiresAt == nil || x.ExpiresAt.After(now) {
			live = append(live, x)
		}
	}
	if len(live) == 0 {
		return func(string, string) string { return "" }, nil
	}
	members, _, err := s.accessSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return func(agentID, metric string) string {
		for _, x := range live {
			if x.Metric != metric {
				continue
			}
			if x.GroupID == "" || members[x.GroupID][agentID] {
				return x.ID
			}
		}
		return ""
	}, nil
}

func newAnomalyView(a store.Anomaly, suppressedBy string) anomalyView {
	m, _ := anomaly.Lookup(a.Metric)
	band := m.Band(anomaly.Baseline{Median: a.BaselineMedian, MAD: a.BaselineMAD, Hours: anomaly.MinBaselineHours})
	return anomalyView{Anomaly: a, MetricLabel: m.Label, Unit: m.Unit, Group: anomaly.GroupKey(a.Metric, a.Direction),
		BandLo: band.Lo, BandHi: band.Hi, Suppressed: suppressedBy != "", SuppressionID: suppressedBy}
}

// GET /api/anomalies — anomalies the caller may see, grouped across the
// fleet and ranked.
func (s *Server) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	switch state {
	case "", "open", "closed", "all":
	default:
		http.Error(w, "state is open, closed or all", http.StatusBadRequest)
		return
	}
	withSuppressed := q.Get("suppressed") == "1"
	access, err := s.anomalyAccess(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	suppressor, err := s.anomalySuppressor(ctx, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.ListAnomalies(ctx, store.AnomalyFilter{State: state, AgentID: q.Get("agent")})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := listAnomaliesResponse{Groups: []anomalyGroupView{}, Anomalies: []anomalyView{},
		Metrics: anomalyMetricViews(access.sensor), MinHours: anomaly.MinBaselineHours,
		SustainMins: int(anomaly.Sustain.Minutes()), RetentionDays: int(anomalyRetention.Closed.Hours() / 24)}
	var items []anomaly.Item
	agentsOf := map[string]string{}
	for _, a := range rows {
		if !access.sees(a.AgentID, a.Metric) {
			continue
		}
		sup := suppressor(a.AgentID, a.Metric)
		if sup != "" {
			resp.Suppressed++
			if !withSuppressed {
				continue
			}
		}
		if a.AcknowledgedAt != nil {
			resp.Acknowledged++
		}
		resp.Anomalies = append(resp.Anomalies, newAnomalyView(a, sup))
		agentsOf[a.ID] = a.AgentID
		// Grouping is of what is happening now; a closed anomaly is
		// history and is listed, not ranked.
		if a.EndedAt == nil {
			items = append(items, anomaly.Item{ID: a.ID, AgentID: a.AgentID, Metric: a.Metric, Direction: a.Direction,
				Level: a.Severity, Score: a.Score, Change: a.Change, Quiet: sup != "" || a.AcknowledgedAt != nil})
		}
	}
	for _, g := range anomaly.GroupItems(items) {
		m, _ := anomaly.Lookup(g.Metric)
		v := anomalyGroupView{ID: g.Key, Metric: g.Metric, MetricLabel: m.Label, Direction: g.Direction,
			Endpoints: g.Endpoints, Active: g.Active, Rank: g.Rank, Severity: g.Level,
			Change: g.Change, ChangeEndpoints: g.ChangeEndpoints, AnomalyIDs: g.IDs, AgentIDs: []string{}}
		for _, id := range g.IDs {
			v.AgentIDs = append(v.AgentIDs, agentsOf[id])
		}
		resp.Groups = append(resp.Groups, v)
	}
	baselines, err := s.store.ListAnomalyBaselines(ctx, q.Get("agent"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ready, seen := map[string]bool{}, map[string]bool{}
	for _, b := range baselines {
		if !access.sees(b.AgentID, b.Metric) {
			continue
		}
		seen[b.AgentID] = true
		if b.Hours >= anomaly.MinBaselineHours {
			ready[b.AgentID] = true
		}
	}
	resp.Tracked, resp.Learning = len(seen), len(seen)-len(ready)
	writeJSONResponse(w, resp)
}

// GET /api/anomalies/{id} — one anomaly with its endpoint's recent values
// and baseline band, for the chart.
func (s *Server) handleGetAnomaly(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := s.store.GetAnomaly(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	access, err := s.anomalyAccess(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// One the caller may not see is one that does not exist, as far as
	// they can tell.
	if a == nil || !access.sees(a.AgentID, a.Metric) {
		http.Error(w, "no such anomaly", http.StatusNotFound)
		return
	}
	now := time.Now()
	suppressor, err := s.anomalySuppressor(ctx, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m, _ := anomaly.Lookup(a.Metric)
	resp := anomalyDetailResponse{Anomaly: newAnomalyView(*a, suppressor(a.AgentID, a.Metric)),
		Samples: []anomalyPoint{}, Others: []anomalyView{}}
	bs, err := s.store.ListAnomalyBaselines(ctx, a.AgentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, b := range bs {
		if b.Metric == a.Metric {
			resp.Baseline = anomaly.Baseline{Median: b.Median, MAD: b.MAD, Hours: b.Hours}
		}
	}
	resp.Ready = resp.Baseline.Ready()
	resp.Band = m.Band(resp.Baseline)
	samples, err := s.store.ListAnomalySamples(ctx, now.Add(-24*time.Hour), a.AgentID, a.Metric)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, x := range samples {
		resp.Samples = append(resp.Samples, anomalyPoint{At: x.At, Value: x.Value})
	}
	if resp.Hours, err = s.store.ListAnomalyHours(ctx, a.AgentID, a.Metric, now.Add(-anomaly.BaselineWindow)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	others, err := s.store.ListAnomalies(ctx, store.AnomalyFilter{State: "open", AgentID: a.AgentID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, o := range others {
		if o.ID != a.ID && access.sees(o.AgentID, o.Metric) {
			resp.Others = append(resp.Others, newAnomalyView(o, suppressor(o.AgentID, o.Metric)))
		}
	}
	writeJSONResponse(w, resp)
}

// ackAnomaliesRequest is the body of POST /api/anomalies/ack.
type ackAnomaliesRequest struct {
	IDs  []string `json:"ids" api:"required"`
	Note string   `json:"note"` // what was found, for whoever looks next
}

// ackAnomaliesResponse is what POST /api/anomalies/ack answers.
type ackAnomaliesResponse struct {
	// Acknowledged are the ids this call acknowledged; one already
	// acknowledged, or one the caller may not see, is left out.
	Acknowledged []string `json:"acknowledged"`
}

// POST /api/anomalies/ack — mark anomalies as looked at. They stay
// listed, and stop counting toward their group's rank.
func (s *Server) handleAckAnomalies(w http.ResponseWriter, r *http.Request) {
	var req ackAnomaliesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.IDs) == 0 || len(req.IDs) > 5000 || len(req.Note) > 1000 {
		http.Error(w, "ids must name 1 to 5000 anomalies and note be at most 1000 characters", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	access, err := s.anomalyAccess(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var allowed []string
	hosts := map[string]bool{}
	for _, id := range req.IDs {
		a, err := s.store.GetAnomaly(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if a != nil && access.sees(a.AgentID, a.Metric) {
			allowed = append(allowed, id)
			hosts[a.Hostname] = true
		}
	}
	done := []string{}
	if len(allowed) > 0 {
		who := auth.CurrentUser(ctx).Username
		if done, err = s.store.AcknowledgeAnomalies(ctx, allowed, who, req.Note); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(done) > 0 {
			names := make([]string, 0, len(hosts))
			for h := range hosts {
				names = append(names, h)
			}
			s.audit(ctx, auditEvent{Action: "anomalies.acknowledge", Actor: who,
				Target: strings.Join(capList(names, 10), ", "),
				Detail: map[string]any{"ids": done, "note": req.Note}})
		}
	}
	writeJSONResponse(w, ackAnomaliesResponse{Acknowledged: done})
}

// capList is the first n of xs, with a count of the rest.
func capList(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	out := append([]string(nil), xs[:n]...)
	return append(out, "and "+strconv.Itoa(len(xs)-n)+" more")
}

// listAnomalySuppressionsResponse is what GET /api/anomalies/suppressions
// answers.
type listAnomalySuppressionsResponse struct {
	Suppressions []anomalySuppressionView `json:"suppressions"`
}

// anomalySuppressionView is a suppression with its group's name.
type anomalySuppressionView struct {
	store.AnomalySuppression
	MetricLabel string `json:"metric_label"`
	// GroupName is the computer group's name; empty with GroupID set
	// means the group was deleted and the suppression covers nothing.
	GroupName string `json:"group_name"`
	Expired   bool   `json:"expired"`
}

// GET /api/anomalies/suppressions — every suppression.
func (s *Server) handleListAnomalySuppressions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sups, err := s.store.ListAnomalySuppressions(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := s.store.ListComputerGroups(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := map[string]string{}
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	now := time.Now()
	out := listAnomalySuppressionsResponse{Suppressions: []anomalySuppressionView{}}
	for _, x := range sups {
		m, _ := anomaly.Lookup(x.Metric)
		out.Suppressions = append(out.Suppressions, anomalySuppressionView{AnomalySuppression: x, MetricLabel: m.Label,
			GroupName: names[x.GroupID], Expired: x.ExpiresAt != nil && !x.ExpiresAt.After(now)})
	}
	writeJSONResponse(w, out)
}

// createAnomalySuppressionRequest is the body of POST
// /api/anomalies/suppressions.
type createAnomalySuppressionRequest struct {
	Metric string `json:"metric" api:"required"` // a metric key from GET /api/anomalies
	// GroupID is the computer group to suppress on; empty means every
	// endpoint, which only someone whose management rights cover the
	// whole fleet may do.
	GroupID string `json:"group_id"`
	Reason  string `json:"reason" api:"required"`
	// Days until it lapses; 0 keeps it until removed.
	Days int `json:"days"`
}

// POST /api/anomalies/suppressions — stop ranking one metric's anomalies
// on a computer group.
func (s *Server) handleCreateAnomalySuppression(w http.ResponseWriter, r *http.Request) {
	var req createAnomalySuppressionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Metric == "" {
		http.Error(w, "metric is required", http.StatusBadRequest)
		return
	}
	m, ok := anomaly.Lookup(req.Metric)
	if !ok {
		http.Error(w, "unknown metric", http.StatusBadRequest)
		return
	}
	if req.Reason == "" || len(req.Reason) > 500 || req.Days < 0 || req.Days > 365 {
		http.Error(w, "a reason (up to 500 characters) is required, and days is 0 to 365", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	target, err := s.anomalySuppressionTarget(ctx, req.GroupID)
	if errors.As(err, new(outsideScopeError)) {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if target == "" {
		http.Error(w, "no such computer group", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(ctx).Username
	x := store.AnomalySuppression{ID: newID("asup-"), Metric: m.Key, GroupID: req.GroupID, Reason: req.Reason,
		CreatedBy: who, CreatedAt: time.Now().UTC()}
	if req.Days > 0 {
		exp := x.CreatedAt.Add(time.Duration(req.Days) * 24 * time.Hour)
		x.ExpiresAt = &exp
	}
	if err := s.store.CreateAnomalySuppression(ctx, x); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "anomalies.suppress", Actor: who, Target: m.Label + " on " + target, Severity: "notice",
		Detail: map[string]any{"id": x.ID, "metric": m.Key, "group_id": req.GroupID, "reason": req.Reason, "days": req.Days}})
	w.WriteHeader(http.StatusCreated)
	writeJSONResponse(w, x)
}

// outsideScopeError refuses a suppression on endpoints the caller does
// not manage.
type outsideScopeError string

func (e outsideScopeError) Error() string { return string(e) }

// anomalySuppressionTarget names the endpoints a suppression on groupID
// covers ("" for a group that no longer exists), after checking the
// caller manages all of them: a suppression hides evidence from
// everybody, so it is limited to what the caller could act on.
func (s *Server) anomalySuppressionTarget(ctx context.Context, groupID string) (string, error) {
	scope, err := s.endpointScope(ctx)
	if err != nil {
		return "", err
	}
	if groupID == "" {
		if scope != nil {
			return "", outsideScopeError("a suppression on every endpoint needs management rights over the whole fleet; name a computer group")
		}
		return "every endpoint", nil
	}
	g, err := s.store.GetComputerGroup(ctx, groupID)
	if err != nil {
		return "", err
	}
	name := ""
	if g != nil {
		name = g.Name
	}
	if scope != nil {
		members, _, err := s.accessSnapshot(ctx)
		if err != nil {
			return "", err
		}
		for id := range members[groupID] {
			if !scope[id] {
				return "", outsideScopeError("the group has endpoints outside your management rights")
			}
		}
	}
	return name, nil
}

// DELETE /api/anomalies/suppressions/{id} — lift a suppression.
func (s *Server) handleDeleteAnomalySuppression(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	sups, err := s.store.ListAnomalySuppressions(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found *store.AnomalySuppression
	for i := range sups {
		if sups[i].ID == id {
			found = &sups[i]
		}
	}
	if found == nil {
		http.Error(w, "no such suppression", http.StatusNotFound)
		return
	}
	if _, err := s.anomalySuppressionTarget(ctx, found.GroupID); errors.As(err, new(outsideScopeError)) {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	x, err := s.store.DeleteAnomalySuppression(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if x == nil {
		http.Error(w, "no such suppression", http.StatusNotFound)
		return
	}
	m, _ := anomaly.Lookup(x.Metric)
	s.audit(ctx, auditEvent{Action: "anomalies.unsuppress", Actor: auth.CurrentUser(ctx).Username, Target: m.Label, Severity: "notice",
		Detail: map[string]any{"id": x.ID, "metric": x.Metric, "group_id": x.GroupID}})
	w.WriteHeader(http.StatusNoContent)
}
