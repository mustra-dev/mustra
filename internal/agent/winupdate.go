package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// What Windows Update offers besides quality and security updates, told
// apart so that installing them is a separate decision.
//
// The search the agent has always run ("IsInstalled=0 and IsHidden=0",
// which is also the documented default) names no Type, so it returns
// software and driver updates alike, and feature updates where Windows
// Update or WSUS offers them. They used to be listed, and installed, as
// ordinary patches. Classified, they are reported with what identifies
// them, and installed only when a patch list opts in
// (internal/patchpolicy) and the command says so (proto.AgentCommand
// IncludeDrivers, FeatureTarget).
//
// Sources (Microsoft Learn):
//   - IUpdateSearcher::Search, the criteria language and its default:
//     https://learn.microsoft.com/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
//   - IUpdate.Type, UpdateType: utSoftware = 1, utDriver = 2:
//     https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-updatetype
//   - IWindowsDriverUpdate (DriverClass, DriverManufacturer, DriverModel,
//     DriverProvider, DriverVerDate; no version property):
//     https://learn.microsoft.com/windows/win32/api/wuapi/nn-wuapi-iwindowsdriverupdate
//   - InstallationRebootBehavior: irbNeverReboots = 0,
//     irbAlwaysRequiresReboot = 1, irbCanRequestReboot = 2:
//     https://learn.microsoft.com/windows/win32/api/wuapi/ne-wuapi-installationrebootbehavior
//   - Classifications are categories with Type "UpdateClassification"
//     (WSUS Classification GUIDs, which explains searching by them):
//     https://learn.microsoft.com/previous-versions/windows/desktop/ff357803(v=vs.85)
//     That archived list predates the Upgrades classification, which
//     carries feature updates, and omits Drivers. Their IDs below
//     (Upgrades 3689bdc8-..., Drivers ebfc1fc5-...) are the ones WSUS and
//     Windows Update report, not taken from a Microsoft reference page, so
//     the classification's name and, for drivers, IUpdate.Type are checked
//     as well, and a feature update is also recognised by its title.
//   - Hotpatch updates are the security updates that "install and take
//     effect without requiring you to restart the device". Microsoft's
//     update titles call them "... Security Hotpatch Update ..." (the
//     release notes and update history list them under that name); the
//     agent relies on that word in the title:
//     https://learn.microsoft.com/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates

// wuaSearchScript lists pending updates with what classifies them. Driver
// properties exist only on driver updates (IWindowsDriverUpdate), so they
// are read for Type 2 alone; each read is guarded so one odd update cannot
// fail the whole list.
const wuaSearchScript = `
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
$out = @()
foreach ($u in $r.Updates) {
  $severity = ""
  if ($u.MsrcSeverity) { $severity = $u.MsrcSeverity }
  $cats = @()
  foreach ($c in $u.Categories) { $cats += [PSCustomObject]@{ Id = [string]$c.CategoryID; Name = [string]$c.Name; Type = [string]$c.Type } }
  $o = [ordered]@{ Title = $u.Title; Severity = $severity; Type = 0; Categories = $cats; RebootBehavior = -1 }
  try { $o.Type = [int]$u.Type } catch {}
  try { $o.RebootBehavior = [int]$u.InstallationBehavior.RebootBehavior } catch {}
  if ($o.Type -eq 2) {
    try { $o.DriverClass = [string]$u.DriverClass } catch {}
    try { $o.DriverManufacturer = [string]$u.DriverManufacturer } catch {}
    try { $o.DriverProvider = [string]$u.DriverProvider } catch {}
    try { $o.DriverModel = [string]$u.DriverModel } catch {}
    try { $o.DriverDate = ([datetime]$u.DriverVerDate).ToString('yyyy-MM-dd') } catch {}
  }
  $out += [PSCustomObject]$o
}
$out | ConvertTo-Json -Compress -Depth 4`

// wuaUpdate is one entry of wuaSearchScript's output. Agents before the
// split ran a script that printed only Title and Severity; the other
// fields then decode as zero and the update is ordinary.
type wuaUpdate struct {
	Title              string          `json:"Title"`
	Severity           string          `json:"Severity"`
	Type               int             `json:"Type"`
	Categories         json.RawMessage `json:"Categories"`
	RebootBehavior     int             `json:"RebootBehavior"`
	DriverClass        string          `json:"DriverClass"`
	DriverManufacturer string          `json:"DriverManufacturer"`
	DriverProvider     string          `json:"DriverProvider"`
	DriverModel        string          `json:"DriverModel"`
	DriverDate         string          `json:"DriverDate"`
}

type wuaCategory struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
	Type string `json:"Type"`
}

const (
	wuaTypeDriver        = 2
	wuaUpgradesCategory  = "3689bdc8-b205-4af4-8d4a-a63924c5e9d5"
	wuaDriversCategory   = "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0"
	wuaClassificationTyp = "UpdateClassification"
)

// categories reads Categories as PowerShell writes it: an array, or a
// lone object when there was exactly one.
func (u wuaUpdate) categories() []wuaCategory {
	raw := bytes.TrimSpace(u.Categories)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var many []wuaCategory
	if raw[0] == '[' {
		_ = json.Unmarshal(raw, &many)
		return many
	}
	var one wuaCategory
	if json.Unmarshal(raw, &one) == nil {
		return []wuaCategory{one}
	}
	return nil
}

func (u wuaUpdate) classifiedAs(id, name string) bool {
	for _, c := range u.categories() {
		if strings.EqualFold(strings.TrimSpace(c.ID), id) {
			return true
		}
		if strings.EqualFold(c.Type, wuaClassificationTyp) && strings.EqualFold(strings.TrimSpace(c.Name), name) {
			return true
		}
	}
	return false
}

// featureTitle matches the way Microsoft names a Windows version upgrade:
// "Feature update to Windows 11, version 24H2", and on WSUS "Windows 11
// (business editions), version 24H2 x64 2024-10B".
var featureTitle = regexp.MustCompile(`(?i)\b(Windows (?:1[01]|Server \d{4}))\b[^,]*,\s*version\s+(\d{2}H[12]|\d{4})\b`)

// featureTarget is the product and version a feature update moves to, as
// its title says; empty when it does not say.
func featureTarget(title string) (product, version string) {
	m := featureTitle.FindStringSubmatch(title)
	if m == nil {
		return "", ""
	}
	return m[1], strings.ToUpper(m[2])
}

var driverVersion = regexp.MustCompile(`^\d+(\.\d+){1,4}$`)

// driverTitleVersion reads the driver version from a driver update's
// title ("Intel Corporation - Display - 32.0.101.6000"), the only place
// Windows Update gives it.
func driverTitleVersion(title string) string {
	parts := strings.Split(title, " - ")
	if len(parts) < 2 {
		return ""
	}
	if v := strings.TrimSpace(parts[len(parts)-1]); driverVersion.MatchString(v) {
		return v
	}
	return ""
}

// isHotpatchTitle: Microsoft names hotpatches as such ("2025-11 Security
// Hotpatch Update for Windows 11 Enterprise Version 24H2 ..."), and the
// name is what both the search and the install result carry.
func isHotpatchTitle(title string) bool {
	return strings.Contains(strings.ToLower(title), "hotpatch")
}

// classifyWindowsUpdate turns one search result into the patch the server
// sees.
func classifyWindowsUpdate(u wuaUpdate) proto.PatchInfo {
	p := proto.PatchInfo{Name: u.Title}
	if u.Severity != "" {
		p.Severity = "security"
	}
	switch {
	case u.Type == wuaTypeDriver || u.classifiedAs(wuaDriversCategory, "Drivers"):
		p.Category = proto.PatchCategoryDriver
		p.NewVersion = driverTitleVersion(u.Title)
		d := proto.DriverUpdate{Class: u.DriverClass, Manufacturer: u.DriverManufacturer, Provider: u.DriverProvider, Model: u.DriverModel, Date: u.DriverDate}
		if d != (proto.DriverUpdate{}) {
			p.Driver = &d
		}
	case u.classifiedAs(wuaUpgradesCategory, "Upgrades") || strings.HasPrefix(strings.ToLower(u.Title), "feature update to windows"):
		p.Category = proto.PatchCategoryFeature
		p.TargetProduct, p.TargetVersion = featureTarget(u.Title)
		p.NewVersion = p.TargetVersion
		p.RestartRequired = true
	default:
		// A hotpatch never restarts; Windows says so in its reboot
		// behaviour too, but the title is what the install result names,
		// so the title decides and an "always reboots" answer overrides it.
		p.Hotpatch = isHotpatchTitle(u.Title) && u.RebootBehavior != 1
	}
	return p
}

// decodeWUASearch reads wuaSearchScript's output: an array, a lone object
// when there was one update, or nothing at all when there were none.
func decodeWUASearch(out []byte) ([]proto.PatchInfo, error) {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var raw []wuaUpdate
	if trimmed[0] == '{' {
		var one wuaUpdate
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("decode windows update search output: %w", err)
		}
		raw = []wuaUpdate{one}
	} else if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fmt.Errorf("decode windows update search output: %w", err)
	}
	patches := make([]proto.PatchInfo, 0, len(raw))
	for _, u := range raw {
		patches = append(patches, classifyWindowsUpdate(u))
	}
	return patches, nil
}

// patchApplyOptions is what an apply_patches command says beyond the
// names: whether macOS goes to an MDM, and which Windows drivers and
// feature update a patch list opted in to.
type patchApplyOptions struct {
	ViaMDM         bool
	IncludeDrivers bool
	FeatureTarget  string
}

// windowsSelection decides what a Windows patch job installs: the named
// updates, or every pending one when none are named, less the drivers and
// feature updates the command did not opt in to. eula lists the ones whose
// licence terms the job accepts: only drivers and the feature update an
// administrator opted in to, so an ordinary update behaves as it always
// has. A name that is not pending is kept, as before; the install script
// simply does not find it.
func windowsSelection(pending []proto.PatchInfo, names []string, opts patchApplyOptions) (install, eula, skipped, notes []string) {
	byName := make(map[string]proto.PatchInfo, len(pending))
	for _, p := range pending {
		byName[p.Name] = p
	}
	candidates := names
	if len(candidates) == 0 {
		for _, p := range pending {
			candidates = append(candidates, p.Name)
		}
	}
	feature := ""
	for _, n := range candidates {
		if slices.Contains(install, n) || slices.Contains(skipped, n) {
			continue
		}
		p := byName[n]
		switch p.Category {
		case proto.PatchCategoryDriver:
			if !opts.IncludeDrivers {
				skipped = append(skipped, n)
				notes = append(notes, "Left driver update "+n+": no patch list opts this endpoint in to driver updates.")
				continue
			}
			eula = append(eula, n)
		case proto.PatchCategoryFeature:
			switch {
			case opts.FeatureTarget == "":
				skipped = append(skipped, n)
				notes = append(notes, "Left feature update "+n+": no patch list targets a Windows version for this endpoint.")
				continue
			case p.TargetVersion == "" || !strings.EqualFold(p.TargetVersion, opts.FeatureTarget):
				skipped = append(skipped, n)
				notes = append(notes, fmt.Sprintf("Left feature update %s: the patch list targets %s, not this one.", n, opts.FeatureTarget))
				continue
			case feature != "":
				skipped = append(skipped, n)
				notes = append(notes, "Left feature update "+n+": one Windows upgrade per job, and "+feature+" is in this one.")
				continue
			}
			feature = n
			eula = append(eula, n)
		}
		install = append(install, n)
	}
	return install, eula, skipped, notes
}

// installableByDefault is the pending updates a job with no names would
// install: the targets the check afterwards looks for.
func installableByDefault(pending []proto.PatchInfo, opts patchApplyOptions) []string {
	install, _, _, _ := windowsSelection(pending, nil, opts)
	return install
}

// skipRestartForHotpatches says a job that would restart should not: the
// updates it installed were all hotpatches, which take effect without
// one, and nothing else asked for a restart. "always" is the case it
// matters for; "if_required" already finds no restart required.
func skipRestartForHotpatches(mode string, required bool, installed []string, blocked string) bool {
	if mode == "" || blocked != "" || required || len(installed) == 0 {
		return false
	}
	for _, n := range installed {
		if !isHotpatchTitle(n) {
			return false
		}
	}
	return true
}
