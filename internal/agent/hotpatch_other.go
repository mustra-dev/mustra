//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectHotpatch: hotpatching is a Windows mechanism. The sensor loop is
// not started elsewhere; a deploy check that asks for it is told why.
func collectHotpatch(context.Context) ([]proto.HotpatchStatus, error) {
	return nil, errors.New("the hotpatch sensor is collected on Windows only")
}
