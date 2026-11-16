//go:build !linux

package agent

import "context"

// sampleUnits: services are only checked on Linux with systemd so far.
func sampleUnits(context.Context) (map[string]unitState, error) {
	return nil, errUnitsUnsupported
}
