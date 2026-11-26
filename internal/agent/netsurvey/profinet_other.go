//go:build !linux

package netsurvey

import (
	"context"
	"errors"
	"time"
)

// Profinet DCP is layer 2. Sending a raw Ethernet frame needs AF_PACKET,
// which only Linux offers without a packet-capture driver (Npcap, BPF
// devices) the agent does not ship; elsewhere the protocol is reported
// as unsupported rather than approximated.
const profinetSupported = "Profinet DCP needs a raw Ethernet socket, which the agent only has on Linux"

func profinetIdentify(context.Context, *Limiter, string, time.Duration) ([]dcpDevice, error) {
	return nil, errors.New(profinetSupported)
}
