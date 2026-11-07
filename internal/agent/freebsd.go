package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// FreeBSD, and the appliances built on it: OPNsense and TrueNAS CORE.
//
// The parsers here take no build tag, so they are tested on every platform;
// only the FreeBSD switch cases call them.

const (
	opnsenseVersionCmd = "/usr/local/sbin/opnsense-version"
	truenasVersionFile = "/etc/version" // "TrueNAS-13.0-U6.1 (…)" on CORE
	freebsdRCScript    = "/usr/local/etc/rc.d/mustra_agent"
	freebsdRCConf      = "/etc/rc.conf.d/mustra_agent"
)

// freebsdAppliance names an appliance whose updates come from its own
// updater, with the sentence that says where. "" on plain FreeBSD.
func freebsdAppliance() (platform, version, updatesFrom string) {
	if _, err := os.Stat(opnsenseVersionCmd); err == nil {
		v, _ := exec.Command(opnsenseVersionCmd, "-v").Output()
		return "opnsense", strings.TrimSpace(string(v)), "OPNsense updates install from its own updater (System → Firmware → Updates), not from the agent"
	}
	if raw, err := os.ReadFile(truenasVersionFile); err == nil && bytes.HasPrefix(raw, []byte("TrueNAS")) {
		v, _, _ := strings.Cut(strings.TrimSpace(string(raw)), " ")
		return "truenas", strings.TrimPrefix(v, "TrueNAS-"), "TrueNAS updates install from its own updater (System → Update), not from the agent"
	}
	return "", "", ""
}

// collectServicesFreeBSD lists the rc.d services enabled in rc.conf and
// whether each is running. `service -e` prints their script paths.
func collectServicesFreeBSD(ctx context.Context) ([]proto.ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "service", "-e").Output()
	if err != nil {
		return nil, fmt.Errorf("service -e: %w", err)
	}
	services := []proto.ServiceInfo{}
	for _, script := range strings.Fields(string(out)) {
		name := filepath.Base(script)
		status := "stopped"
		// onestatus answers whatever rc.conf says; exit 0 means running.
		if exec.CommandContext(ctx, script, "onestatus").Run() == nil {
			status = "running"
		} else if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		services = append(services, proto.ServiceInfo{Name: name, Status: status, StartType: "enabled"})
	}
	return services, nil
}

// collectAppsFreeBSD reads installed packages: name, version and install
// time (%t, seconds since the epoch).
func collectAppsFreeBSD(ctx context.Context) ([]proto.InstalledApp, error) {
	out, err := exec.CommandContext(ctx, "pkg", "query", "%n\t%v\t%t").Output()
	if err != nil {
		return nil, fmt.Errorf("pkg query: %w", err)
	}
	apps := parseTabbedApps(out, rpmInstallDate)
	if apps == nil {
		apps = []proto.InstalledApp{}
	}
	return apps, nil
}

// collectPatchesFreeBSD lists packages with a newer version in the remote
// catalogue. pkg refreshes the catalogue first when it is out of date, the
// way the agent refreshes apt's lists. Base system updates (freebsd-update)
// are not packages and are not read.
func collectPatchesFreeBSD(ctx context.Context) ([]proto.PatchInfo, error) {
	if _, _, updatesFrom := freebsdAppliance(); strings.HasPrefix(updatesFrom, "TrueNAS") {
		// TrueNAS disables pkg's repositories; its updates are whole images.
		return nil, errors.New(updatesFrom)
	}
	out, err := exec.CommandContext(ctx, "pkg", "version", "-v", "-R", "-l", "<").Output()
	if err != nil {
		return nil, fmt.Errorf("pkg version: %w", err)
	}
	return parsePkgVersion(out), nil
}

// parsePkgVersion reads `pkg version -vRl '<'`:
//
//	curl-8.9.1                          <   needs updating (remote has 8.10.0)
//
// A package's version never contains a dash, so the last one ends its name.
func parsePkgVersion(out []byte) []proto.PatchInfo {
	patches := []proto.PatchInfo{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1] != "<" {
			continue
		}
		i := strings.LastIndex(f[0], "-")
		if i <= 0 {
			continue
		}
		p := proto.PatchInfo{Name: f[0][:i], CurrentVersion: f[0][i+1:]}
		line := sc.Text()
		if _, rest, ok := strings.Cut(line, "(remote has "); ok {
			p.NewVersion = strings.TrimSuffix(strings.TrimSpace(rest), ")")
		}
		patches = append(patches, p)
	}
	return patches
}

// applyPatchesFreeBSD upgrades the named packages, or all of them. pkg
// upgrade never installs a package that is not there already.
func applyPatchesFreeBSD(ctx context.Context, names []string, report patchProgress) (patchApplyResult, error) {
	var res patchApplyResult
	if _, _, updatesFrom := freebsdAppliance(); updatesFrom != "" {
		return res, errors.New(updatesFrom)
	}
	report("installing", "", 1)
	out, err := runWithLockRetry(ctx, "installing", report, &res.Attempts, func() (string, error) {
		o, e := exec.CommandContext(ctx, "pkg", append([]string{"upgrade", "-y"}, names...)...).CombinedOutput()
		return string(o), e
	})
	res.Output = out
	if err != nil {
		return res, fmt.Errorf("pkg upgrade: %w", err)
	}
	return res, nil
}

// parseFreeBSDNeighbors needs nothing of its own: arp -an and ndp -an print
// the same shapes as on macOS, which neighbors.go already reads.
