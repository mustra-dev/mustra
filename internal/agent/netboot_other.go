//go:build !linux && !windows

package agent

import (
	"context"

	"github.com/mustra-dev/mustra/internal/proto"
)

// setNextBootNetwork: macOS and FreeBSD have no supported way for the
// agent to choose a one-time network boot (Apple's NetBoot is gone from
// Apple silicon), so a person at the machine chooses it.
func setNextBootNetwork(context.Context, string) (proto.NetBootResult, error) {
	return netBootManual("This operating system offers the agent no way to choose a one-time network boot."), nil
}
