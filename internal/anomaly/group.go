package anomaly

import (
	"sort"
)

// Item is one anomaly as grouping sees it.
type Item struct {
	ID        string
	AgentID   string
	Metric    string
	Direction string
	Level     string
	Score     float64
	// Change is the software or agent change the endpoint went through
	// shortly before the anomaly began, if any.
	Change string
	// Quiet items (acknowledged or suppressed) are listed with their
	// group but add nothing to its rank: somebody has already looked.
	Quiet bool
}

// Group is the same anomaly on several endpoints.
type Group struct {
	// Key is stable for a metric and direction ("cpu-high"), so a group
	// has a URL that survives its members changing.
	Key       string
	Metric    string
	Direction string
	Endpoints int
	// Active is how many members are neither acknowledged nor suppressed.
	Active int
	// Rank orders groups: the active members' severity scores summed,
	// which is their average severity times how many endpoints show it.
	Rank  float64
	Level string // the worst active member's level, or the worst overall when none is active
	// Change is the change most members share, when at least two and at
	// least half of them do; ChangeEndpoints says how many.
	Change          string
	ChangeEndpoints int
	IDs             []string
}

// GroupKey is the group an anomaly on this metric in this direction
// belongs to.
func GroupKey(metric, direction string) string { return metric + "-" + direction }

// GroupItems groups anomalies by metric and direction, ranked worst first.
func GroupItems(items []Item) []Group {
	byKey := map[string]*Group{}
	changes := map[string]map[string]int{}
	worstAny := map[string]string{}
	var order []string
	for _, it := range items {
		k := GroupKey(it.Metric, it.Direction)
		g := byKey[k]
		if g == nil {
			g = &Group{Key: k, Metric: it.Metric, Direction: it.Direction}
			byKey[k], changes[k] = g, map[string]int{}
			order = append(order, k)
		}
		g.Endpoints++
		g.IDs = append(g.IDs, it.ID)
		if it.Change != "" {
			changes[k][it.Change]++
		}
		if w, ok := worstAny[k]; !ok || SeverityRank(it.Level) > SeverityRank(w) {
			worstAny[k] = it.Level
		}
		if it.Quiet {
			continue
		}
		g.Active++
		g.Rank += it.Score
		if g.Level == "" || SeverityRank(it.Level) > SeverityRank(g.Level) {
			g.Level = it.Level
		}
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		if g.Level == "" {
			g.Level = worstAny[k]
		}
		for c, n := range changes[k] {
			if n > g.ChangeEndpoints || (n == g.ChangeEndpoints && c < g.Change) {
				g.Change, g.ChangeEndpoints = c, n
			}
		}
		if g.ChangeEndpoints < 2 || 2*g.ChangeEndpoints < g.Endpoints {
			g.Change, g.ChangeEndpoints = "", 0
		}
		g.Rank = float64(int64(g.Rank*10+0.5)) / 10
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rank != out[j].Rank {
			return out[i].Rank > out[j].Rank
		}
		if out[i].Endpoints != out[j].Endpoints {
			return out[i].Endpoints > out[j].Endpoints
		}
		return out[i].Key < out[j].Key
	})
	return out
}
