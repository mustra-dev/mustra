//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// setNextBootNetwork sets the firmware boot manager's one-time boot
// sequence to a network entry with bcdedit. Like BootNext, the sequence is
// used for the next start only; the display order is not changed. It
// needs UEFI: on BIOS the firmware namespace does not exist and bcdedit
// says so.
func setNextBootNetwork(ctx context.Context, mac string) (proto.NetBootResult, error) {
	out, err := exec.CommandContext(ctx, "bcdedit.exe", "/enum", "firmware").CombinedOutput()
	if err != nil {
		return netBootManual("bcdedit could not list the firmware's boot entries (this endpoint may boot with BIOS): " + strings.TrimSpace(string(out)) + "."), nil
	}
	e := chooseNetworkEntry(parseBcdeditFirmware(string(out)), mac)
	if e == nil {
		return netBootManual("The firmware lists no network boot entry (network boot may be turned off in its setup)."), nil
	}
	if out, err := exec.CommandContext(ctx, "bcdedit.exe", "/set", "{fwbootmgr}", "bootsequence", e.ID).CombinedOutput(); err != nil {
		return proto.NetBootResult{}, fmt.Errorf("bcdedit /set {fwbootmgr} bootsequence %s failed: %s", e.ID, strings.TrimSpace(string(out)))
	}
	return proto.NetBootResult{Method: "bcdedit", Entry: e.ID + " " + e.Description}, nil
}
