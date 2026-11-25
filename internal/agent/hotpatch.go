package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Hotpatch standing: can this Windows endpoint receive hotpatches, and is
// it enrolled for them. Hotpatches are the monthly security updates that
// install and take effect without a restart.
//
// What Microsoft documents, and what the agent reads for it:
//
//   - Prerequisites for Windows 11 (Windows 11, version 24H2 or later, an
//     Enterprise/Education-class licence, VBS turned on, on Arm64 CHPE
//     turned off with HotPatchRestrictions=1 under Memory Management, and
//     the current quarterly baseline), and how to verify enrolment (the
//     Update/AllowRebootlessUpdates policy a Windows quality update policy
//     with hotpatch allowed sets):
//     https://learn.microsoft.com/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates
//   - VBS state: Win32_DeviceGuard in root\Microsoft\Windows\DeviceGuard,
//     VirtualizationBasedSecurityStatus 0 not enabled, 1 enabled but not
//     running, 2 enabled and running:
//     https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
//   - Windows Server (2025, and 2022 Datacenter: Azure Edition) receives
//     hotpatches through Azure Arc or Azure, not the Windows 11 policy.
//     An enrolled Azure Edition machine carries the "Hotpatch Enrollment
//     Package" targeting key, HKLM\SOFTWARE\Microsoft\Windows
//     NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.amd64,
//     which the agent also reads as enrolment:
//     https://learn.microsoft.com/windows-server/get-started/enable-hotpatch-azure-edition
//
// The edition and build come from HKLM\SOFTWARE\Microsoft\Windows
// NT\CurrentVersion (EditionID, CurrentBuildNumber, UBR, DisplayVersion,
// InstallationType). Enrolment is read where MDM-delivered policies are
// stored, HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update,
// value AllowRebootlessUpdates. Microsoft documents the policy by name
// (the Autopatch page above shows it in the device's event log) but not
// that registry location, so a device enrolled some other way may read as
// not enrolled. Licensing and the quarterly baseline cannot be seen on the
// device at all; they are left out of Eligible and said so in the catalog.

// hotpatchProbeScript reads every source in one PowerShell start. Each
// read is isolated so one that fails blanks only its own field.
const hotpatchProbeScript = `
$o = [ordered]@{ VBS = -1; HotPatchRestrictions = -1; AllowRebootlessUpdates = -1; Errors = @() }
try {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $o.EditionID = [string]$cv.EditionID; $o.ProductName = [string]$cv.ProductName
  $o.CurrentBuild = [string]$cv.CurrentBuildNumber; $o.UBR = [string]$cv.UBR
  $o.DisplayVersion = [string]$cv.DisplayVersion; $o.InstallationType = [string]$cv.InstallationType
} catch { $o.Errors += ("version: " + $_.Exception.Message) }
try {
  $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
  $o.VBS = [int]$dg.VirtualizationBasedSecurityStatus
} catch { $o.Errors += ("Win32_DeviceGuard: " + $_.Exception.Message) }
$mm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue
if ($mm -and $null -ne $mm.HotPatchRestrictions) { $o.HotPatchRestrictions = [int]$mm.HotPatchRestrictions }
$pm = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
if ($pm -and $null -ne $pm.AllowRebootlessUpdates) { $o.AllowRebootlessUpdates = [int]$pm.AllowRebootlessUpdates }
$t = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled'
$o.HotpatchTargeting = (Test-Path "$t\Hotpatch.amd64") -or (Test-Path "$t\Hotpatch.arm64")
$o.Arch = [string]$env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $o.Arch = [string]$env:PROCESSOR_ARCHITEW6432 }
[PSCustomObject]$o | ConvertTo-Json -Compress`

// hotpatchProbe is hotpatchProbeScript's output. -1 is "not there".
type hotpatchProbe struct {
	EditionID              string   `json:"EditionID"`
	ProductName            string   `json:"ProductName"`
	CurrentBuild           string   `json:"CurrentBuild"`
	UBR                    string   `json:"UBR"`
	DisplayVersion         string   `json:"DisplayVersion"`
	InstallationType       string   `json:"InstallationType"`
	VBS                    int      `json:"VBS"`
	HotPatchRestrictions   int      `json:"HotPatchRestrictions"`
	AllowRebootlessUpdates int      `json:"AllowRebootlessUpdates"`
	HotpatchTargeting      bool     `json:"HotpatchTargeting"`
	Arch                   string   `json:"Arch"`
	Errors                 []string `json:"Errors"`
}

// hotpatchMinBuild is Windows 11, version 24H2, and Windows Server 2025.
const hotpatchMinBuild = 26100

func decodeHotpatchProbe(out []byte) (hotpatchProbe, error) {
	var p hotpatchProbe
	if err := json.Unmarshal(out, &p); err != nil {
		return p, fmt.Errorf("decode hotpatch probe: %w", err)
	}
	return p, nil
}

// evaluateHotpatch turns what the probe read into the endpoint's standing.
// Pure, so the rules are tested without a Windows machine.
func evaluateHotpatch(p hotpatchProbe) proto.HotpatchStatus {
	st := proto.HotpatchStatus{
		Edition: p.EditionID, ProductName: p.ProductName, DisplayVersion: p.DisplayVersion,
		Server:   strings.EqualFold(p.InstallationType, "Server") || strings.EqualFold(p.InstallationType, "Server Core"),
		Enrolled: p.AllowRebootlessUpdates == 1 || p.HotpatchTargeting,
		Errors:   p.Errors,
	}
	st.Build = p.CurrentBuild
	if p.UBR != "" && p.CurrentBuild != "" {
		st.Build += "." + p.UBR
	}
	switch strings.ToUpper(p.Arch) {
	case "AMD64":
		st.Arch = "amd64"
	case "ARM64":
		st.Arch = "arm64"
	case "X86":
		st.Arch = "x86"
	default:
		st.Arch = strings.ToLower(p.Arch)
	}
	switch p.VBS {
	case 0:
		st.VBS = "off"
	case 1:
		st.VBS = "enabled"
	case 2:
		st.VBS = "running"
	default:
		st.VBS = "unknown"
	}
	if st.Arch == "arm64" {
		off := p.HotPatchRestrictions == 1
		st.CHPEDisabled = &off
	}

	build, _ := strconv.Atoi(p.CurrentBuild)
	edition := strings.ToLower(p.EditionID)
	azure := strings.Contains(edition, "azure") || strings.Contains(edition, "turbine")
	switch {
	case p.CurrentBuild == "":
		st.Reasons = append(st.Reasons, "the Windows version could not be read")
	case st.Server:
		if build < hotpatchMinBuild && !azure {
			st.Reasons = append(st.Reasons, "Windows Server 2025, or Windows Server 2022 Datacenter: Azure Edition, is required")
		}
	default:
		if build < hotpatchMinBuild {
			st.Reasons = append(st.Reasons, "Windows 11, version 24H2 (build 26100) or later is required")
		}
		// Enterprise, Education, and Enterprise multi-session (ServerRdsh),
		// with their N variants: the editions the eligible licences run.
		if !strings.HasPrefix(edition, "enterprise") && !strings.HasPrefix(edition, "education") && edition != "serverrdsh" {
			st.Reasons = append(st.Reasons, fmt.Sprintf("edition %s is not eligible; hotpatch needs Windows 11 Enterprise or Education", editionOrUnknown(p.EditionID)))
		}
	}
	if st.Arch == "x86" {
		st.Reasons = append(st.Reasons, "hotpatch is offered for x64 and Arm64 only")
	}
	switch st.VBS {
	case "running":
	case "enabled":
		st.Reasons = append(st.Reasons, "virtualization-based security is enabled but not running")
	case "off":
		st.Reasons = append(st.Reasons, "virtualization-based security is off")
	default:
		st.Reasons = append(st.Reasons, "virtualization-based security state could not be read")
	}
	if st.CHPEDisabled != nil && !*st.CHPEDisabled {
		st.Reasons = append(st.Reasons, "on Arm64, CHPE must be turned off (HotPatchRestrictions=1, then a restart)")
	}
	st.Eligible = len(st.Reasons) == 0
	return st
}

func editionOrUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
