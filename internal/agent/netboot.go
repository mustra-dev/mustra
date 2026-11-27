package agent

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Booting from the network once, for OS provisioning's reimage.
//
// The agent sets the firmware's next boot to a network entry — UEFI
// BootNext through efibootmgr on Linux, the firmware boot sequence through
// bcdedit on Windows — and restarts. Neither changes the boot order: the
// machine network-boots once, and the boot server either installs on it
// (it is armed) or sends it back to its disk. Where no network entry can
// be chosen (BIOS, macOS, no entry, no tool), the answer is "manual" with
// what a person at the console does instead; the agent restarts nothing
// then, since a restart into the same disk would only interrupt whoever
// is using it.

// bootEntry is one firmware boot entry the agent could choose.
type bootEntry struct {
	ID          string // efibootmgr's 4-digit hex number, or bcdedit's {GUID}
	Description string
	Text        string // everything the tool printed for the entry
	Active      bool
}

// networkEntryScore rates how good a next-boot choice an entry is for an
// interface with MAC mac (lower case hex, no separators): 0 is not a
// network entry. IPv4 PXE is preferred, because the boot server is
// reached by chainloading iPXE from DHCP; an entry naming the armed
// interface is preferred over any other.
func networkEntryScore(e bootEntry, mac string) int {
	t := strings.ToLower(e.Text + " " + e.Description)
	compact := strings.NewReplacer(":", "", "-", "").Replace(t)
	network := strings.Contains(t, "pxe") || strings.Contains(t, "mac(") || strings.Contains(t, "network") ||
		strings.Contains(t, "ipv4") || strings.Contains(t, "ipv6") || strings.Contains(t, " nic") || strings.Contains(t, "nic(")
	if !network {
		return 0
	}
	score := 10
	if mac != "" && strings.Contains(compact, mac) {
		score += 100
	}
	switch {
	case strings.Contains(t, "ipv6") || strings.Contains(t, "pxev6"):
		score -= 5
	case strings.Contains(t, "ipv4") || strings.Contains(t, "pxev4"):
		score += 5
	}
	if strings.Contains(t, "http") {
		score -= 3
	}
	if e.Active {
		score += 1
	}
	return score
}

// chooseNetworkEntry picks the best network entry, or nil.
func chooseNetworkEntry(entries []bootEntry, mac string) *bootEntry {
	mac = strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(mac))
	var best *bootEntry
	bestScore := 0
	for i := range entries {
		if sc := networkEntryScore(entries[i], mac); sc > bestScore {
			best, bestScore = &entries[i], sc
		}
	}
	return best
}

var efiBootLine = regexp.MustCompile(`^Boot([0-9A-Fa-f]{4})(\*?)\s+(.*)$`)

// parseEfibootmgr reads `efibootmgr -v` output. The description and the
// device path are separated by a tab in every version that prints both.
func parseEfibootmgr(out string) []bootEntry {
	var entries []bootEntry
	for _, line := range strings.Split(out, "\n") {
		m := efiBootLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		desc, _, _ := strings.Cut(m[3], "\t")
		entries = append(entries, bootEntry{ID: strings.ToUpper(m[1]), Description: strings.TrimSpace(desc), Text: m[3], Active: m[2] == "*"})
	}
	return entries
}

var bcdGUID = regexp.MustCompile(`\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}`)

// parseBcdeditFirmware reads `bcdedit /enum firmware` output: blocks
// separated by blank lines, each with its identifier on the first line
// that names a GUID. Field names are localized, so the parser goes by
// shape, not by the words "identifier" and "description"; the description
// is the block's longest value line that is not a GUID list.
func parseBcdeditFirmware(out string) []bootEntry {
	var entries []bootEntry
	for _, block := range splitBlocks(out) {
		if strings.Contains(block, "{fwbootmgr}") || strings.Contains(block, "{bootmgr}") {
			continue // the boot managers, whose display order lists the entries
		}
		lines := strings.Split(block, "\n")
		id := ""
		for _, l := range lines {
			if g := bcdGUID.FindString(l); g != "" {
				id = g
				break
			}
		}
		if id == "" {
			continue
		}
		desc := ""
		for _, l := range lines[min(2, len(lines)):] {
			f := strings.Fields(l)
			if len(f) < 2 || bcdGUID.MatchString(l) || strings.HasPrefix(strings.TrimSpace(l), "{") {
				continue
			}
			v := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), f[0]))
			if len(v) > len(desc) {
				desc = v
			}
		}
		entries = append(entries, bootEntry{ID: id, Description: desc, Text: block, Active: true})
	}
	return entries
}

func splitBlocks(out string) []string {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	var blocks []string
	for _, b := range strings.Split(out, "\n\n") {
		if strings.TrimSpace(b) != "" {
			blocks = append(blocks, strings.TrimSpace(b))
		}
	}
	return blocks
}

// netBootManual is the answer when the agent cannot choose the next boot.
func netBootManual(why string) proto.NetBootResult {
	return proto.NetBootResult{Method: "manual", Instructions: why +
		" Restart the computer and choose network (PXE) boot from the firmware's boot menu (usually F12, F11, F8 or Esc at power-on)."}
}

// runNetBootOnce sets the next boot and, when asked, schedules the
// restart. The restart is at least a minute out, so the reply reaches the
// server before the endpoint goes down.
func (a *Agent) runNetBootOnce(ctx context.Context, job *proto.NetBootJob) proto.AgentCommandResult {
	if job == nil {
		return proto.AgentCommandResult{OK: false, Error: "net_boot_once needs a job"}
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := setNextBootNetwork(sctx, job.MAC)
	if err != nil {
		a.logger.Warn("setting the next boot to the network failed", "error", err)
		return proto.AgentCommandResult{OK: false, Error: err.Error()}
	}
	if res.Method != "manual" && job.Restart {
		minutes := max(1, job.RestartMinutes)
		if err := scheduleRestart(context.WithoutCancel(ctx), minutes, "mustra: this computer restarts to be reinstalled"); err != nil {
			a.logger.Warn("scheduling the reimage restart failed", "error", err)
			res.Instructions = "The next boot is set, but the restart could not be scheduled (" + err.Error() + "); restart the computer to continue."
		} else {
			res.Restarting = true
		}
	}
	a.logger.Warn("next boot set to the network by the console", "method", res.Method, "entry", res.Entry, "restarting", res.Restarting)
	return proto.AgentCommandResult{OK: true, Output: res.Method + " " + res.Entry, NetBoot: &res}
}
