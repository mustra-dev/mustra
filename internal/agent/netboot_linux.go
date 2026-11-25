//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// setNextBootNetwork sets UEFI BootNext to a network entry with
// efibootmgr. BootNext is used once and then cleared by the firmware, so
// the boot order is left as it was.
func setNextBootNetwork(ctx context.Context, mac string) (proto.NetBootResult, error) {
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		return netBootManual("This endpoint boots with BIOS, which has no next-boot setting the agent can change."), nil
	}
	tool, err := exec.LookPath("efibootmgr")
	if err != nil {
		return netBootManual("efibootmgr is not installed on this endpoint."), nil
	}
	out, err := exec.CommandContext(ctx, tool, "-v").CombinedOutput()
	if err != nil {
		return netBootManual("efibootmgr could not read the boot entries: " + strings.TrimSpace(string(out)) + "."), nil
	}
	e := chooseNetworkEntry(parseEfibootmgr(string(out)), mac)
	if e == nil {
		return netBootManual("The firmware lists no network boot entry (network boot may be turned off in its setup)."), nil
	}
	if out, err := exec.CommandContext(ctx, tool, "--bootnext", e.ID).CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			msg = "timed out"
		}
		return proto.NetBootResult{}, fmt.Errorf("efibootmgr --bootnext %s failed: %s", e.ID, msg)
	}
	return proto.NetBootResult{Method: "efibootmgr", Entry: "Boot" + e.ID + " " + e.Description}, nil
}
