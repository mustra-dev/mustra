package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/agent/netsurvey"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Network surveys (internal/agent/netsurvey): the one thing this agent
// does that puts packets on the network on an operator's behalf. One run
// at a time; the job, SNMP secrets included, lives only in this run's
// memory and is never logged or written to disk.

type netSurveyState struct {
	mu      sync.Mutex
	running string // run ID
	cancel  context.CancelFunc
}

// startNetSurvey answers the network_survey command: refuses a second
// concurrent run, otherwise starts this one and returns at once.
func (a *Agent) startNetSurvey(ctx context.Context, job *proto.NetSurveyJob) proto.AgentCommandResult {
	if job == nil || job.RunID == "" || len(job.Subnets) == 0 || len(job.Protocols) == 0 {
		return proto.AgentCommandResult{Error: "network_survey needs a run, subnets and protocols"}
	}
	a.netSurvey.mu.Lock()
	if a.netSurvey.running != "" {
		running := a.netSurvey.running
		a.netSurvey.mu.Unlock()
		return proto.AgentCommandResult{Error: "a network survey is already running on this endpoint (" + running + ")"}
	}
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.netSurvey.running, a.netSurvey.cancel = job.RunID, cancel
	a.netSurvey.mu.Unlock()

	go func() {
		defer cancel()
		// Stop with the agent: the command's ctx is the agent's.
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		a.runNetSurvey(rctx, *job)
		a.netSurvey.mu.Lock()
		a.netSurvey.running, a.netSurvey.cancel = "", nil
		a.netSurvey.mu.Unlock()
	}()
	return proto.AgentCommandResult{OK: true, Output: "survey started"}
}

// cancelNetSurvey stops the run with the given ID, if it is the one
// running.
func (a *Agent) cancelNetSurvey(runID string) proto.AgentCommandResult {
	a.netSurvey.mu.Lock()
	defer a.netSurvey.mu.Unlock()
	if a.netSurvey.running == "" || (runID != "" && runID != a.netSurvey.running) {
		return proto.AgentCommandResult{OK: true, Output: "no such survey is running"}
	}
	a.netSurvey.cancel()
	return proto.AgentCommandResult{OK: true, Output: "survey cancelled"}
}

func (a *Agent) runNetSurvey(ctx context.Context, job proto.NetSurveyJob) {
	a.logger.Info("network survey started", "run", job.RunID, "subnets", job.Subnets, "protocols", job.Protocols,
		"packets_per_second", job.PacketsPerSecond)
	rep := netsurvey.Run(ctx, job, netsurvey.Env{
		Networks: netsurvey.LocalNetworks,
		Neighbors: func(ctx context.Context) map[string]string {
			out := map[string]string{}
			if n, err := collectNeighbors(ctx); err == nil {
				for _, x := range n {
					out[x.IP] = x.MAC
				}
			}
			return out
		},
	})
	job.SNMP = nil
	rep.AgentID = a.agentID
	raw, err := json.Marshal(rep)
	if err != nil {
		a.logger.Error("marshal network survey report failed", "error", err)
		return
	}
	snap := proto.SensorSnapshot{AgentID: a.agentID, Sensor: proto.SensorNetSurvey, Timestamp: time.Now().UTC(), Data: raw}
	payload, _ := json.Marshal(snap)
	// The durable path, like every outcome: a report must survive the
	// broker connection dropping while the run was going on.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if err := a.pub.Publish(pctx, bnats.AgentSensor(a.agentID, string(proto.SensorNetSurvey)), payload); err != nil {
		a.logger.Error("publish network survey report failed", "error", err)
	}
	a.logger.Info("network survey finished", "run", job.RunID, "hosts", rep.HostsPlanned, "probes", rep.Probes,
		"devices", len(rep.Devices), "refused", len(rep.Refused), "timed_out", rep.TimedOut, "cancelled", rep.Cancelled, "error", rep.Error)
	// The probes filled this endpoint's ARP table; report it now rather
	// than at the next interval, so Discover sees the MACs straight away.
	go a.collectAndPublishSensor(context.WithoutCancel(ctx), proto.SensorNeighbors, func(ctx context.Context) (any, error) {
		return collectNeighbors(ctx)
	})
}
