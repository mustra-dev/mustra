package agent

import (
	"strings"
	"testing"
)

func TestEvaluateHotpatch(t *testing.T) {
	eligible := hotpatchProbe{EditionID: "Enterprise", CurrentBuild: "26100", UBR: "4061", DisplayVersion: "24H2",
		InstallationType: "Client", VBS: 2, HotPatchRestrictions: -1, AllowRebootlessUpdates: 1, Arch: "AMD64"}
	for _, c := range []struct {
		name     string
		edit     func(*hotpatchProbe)
		eligible bool
		enrolled bool
		reason   string
	}{
		{"enterprise 24H2 with VBS, enrolled", func(*hotpatchProbe) {}, true, true, ""},
		{"not enrolled", func(p *hotpatchProbe) { p.AllowRebootlessUpdates = -1 }, true, false, ""},
		{"23H2", func(p *hotpatchProbe) { p.CurrentBuild = "22631" }, false, true, "24H2"},
		{"Pro", func(p *hotpatchProbe) { p.EditionID = "Professional" }, false, true, "edition Professional"},
		{"Education N", func(p *hotpatchProbe) { p.EditionID = "EducationN" }, true, true, ""},
		{"VBS configured, not running", func(p *hotpatchProbe) { p.VBS = 1 }, false, true, "not running"},
		{"VBS off", func(p *hotpatchProbe) { p.VBS = 0 }, false, true, "is off"},
		{"VBS unreadable", func(p *hotpatchProbe) { p.VBS = -1 }, false, true, "could not be read"},
		{"Arm64 with CHPE", func(p *hotpatchProbe) { p.Arch = "ARM64" }, false, true, "CHPE"},
		{"Arm64 without CHPE", func(p *hotpatchProbe) { p.Arch = "ARM64"; p.HotPatchRestrictions = 1 }, true, true, ""},
		{"Server 2025", func(p *hotpatchProbe) {
			p.InstallationType, p.EditionID, p.AllowRebootlessUpdates, p.HotpatchTargeting = "Server", "ServerDatacenter", -1, true
		}, true, true, ""},
		{"Server 2022 Azure Edition", func(p *hotpatchProbe) {
			p.InstallationType, p.EditionID, p.CurrentBuild = "Server Core", "ServerTurbineCor", "20348"
		}, true, true, ""},
		{"Server 2022 Datacenter", func(p *hotpatchProbe) {
			p.InstallationType, p.EditionID, p.CurrentBuild = "Server", "ServerDatacenter", "20348"
		}, false, true, "Server 2025"},
		{"version unreadable", func(p *hotpatchProbe) { p.CurrentBuild = "" }, false, true, "could not be read"},
	} {
		p := eligible
		c.edit(&p)
		st := evaluateHotpatch(p)
		if st.Eligible != c.eligible || st.Enrolled != c.enrolled {
			t.Errorf("%s: eligible=%v enrolled=%v reasons=%v", c.name, st.Eligible, st.Enrolled, st.Reasons)
		}
		if c.reason != "" && !strings.Contains(strings.Join(st.Reasons, "\n"), c.reason) {
			t.Errorf("%s: reasons %v lack %q", c.name, st.Reasons, c.reason)
		}
	}
	st := evaluateHotpatch(eligible)
	if st.Build != "26100.4061" || st.Arch != "amd64" || st.VBS != "running" || st.CHPEDisabled != nil {
		t.Errorf("fields: %+v", st)
	}
}

func TestDecodeHotpatchProbe(t *testing.T) {
	p, err := decodeHotpatchProbe([]byte(`{"VBS":2,"HotPatchRestrictions":-1,"AllowRebootlessUpdates":-1,"Errors":[],"EditionID":"Enterprise","CurrentBuild":"26100","UBR":"1","DisplayVersion":"24H2","InstallationType":"Client","HotpatchTargeting":false,"Arch":"AMD64"}`))
	if err != nil || p.EditionID != "Enterprise" || p.VBS != 2 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := decodeHotpatchProbe([]byte(`not json`)); err == nil {
		t.Fatal("garbage decoded")
	}
}
