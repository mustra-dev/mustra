package agent

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

const apkDBFixture = `C:Q1VUDpgJeUrOn4O34ZOihImI9hYis=
P:acl-libs
V:2.3.2-r1
A:x86_64
o:acl
t:1735923921
F:usr
R:libacl.so.1
Z:Q1tO6n8mNmxrWYcNE/D0ES1Q4VF9Y=

C:Q11ELKnukdume+ToP0JdC1XXr46jM=
P:busybox-binsh
V:1.37.0-r18
A:x86_64
o:busybox

P:linux-virt
V:6.12.30-r0
A:x86_64
o:linux-lts
`

func TestParseApkInstalled(t *testing.T) {
	got := parseApkInstalled(apkDBFixture)
	want := []apkPackage{
		{Name: "acl-libs", Version: "2.3.2-r1", Arch: "x86_64", Origin: "acl", BuildTime: 1735923921},
		{Name: "busybox-binsh", Version: "1.37.0-r18", Arch: "x86_64", Origin: "busybox"},
		{Name: "linux-virt", Version: "6.12.30-r0", Arch: "x86_64", Origin: "linux-lts"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseApkVersion(t *testing.T) {
	out := "Installed:                                Available:\n" +
		"busybox-binsh-1.37.0-r18                < 1.37.0-r20 \n" +
		"linux-virt-6.12.30-r0                   < 6.12.41-r0 \n" +
		"not-installed-1.0-r0                    < 1.1-r0 \n" +
		"acl-libs-2.3.2-r1                       = 2.3.2-r1 \n"
	want := []proto.PatchInfo{
		{Name: "busybox-binsh", CurrentVersion: "1.37.0-r18", NewVersion: "1.37.0-r20"},
		{Name: "linux-virt", CurrentVersion: "6.12.30-r0", NewVersion: "6.12.41-r0", RestartRequired: true},
	}
	if got := parseApkVersion(out, parseApkInstalled(apkDBFixture)); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestApkAppsReportOrigin(t *testing.T) {
	apps := apkApps(parseApkInstalled(apkDBFixture))
	want := proto.InstalledApp{Name: "busybox-binsh", Version: "1.37.0-r18", Source: "busybox", SourceVersion: "1.37.0-r18"}
	if len(apps) != 3 || apps[1] != want {
		t.Errorf("got %+v, want busybox-binsh as %+v", apps, want)
	}
}

func TestParseApkPins(t *testing.T) {
	world := "alpine-base\nopenssh\nopenssh-server-common><Q1mOMJ36GJLWLxCFnayX3anhclpjk=\nnginx=1.26.2-r0\ncurl>=8\nphp83~8.3\n!busybox-extras\nbash@edge\nzlib<1.4\n"
	want := []apkPin{
		{"openssh-server-common", "openssh-server-common><Q1mOMJ36GJLWLxCFnayX3anhclpjk="},
		{"nginx", "nginx=1.26.2-r0"},
		{"php83", "php83~8.3"},
		{"zlib", "zlib<1.4"},
	}
	if got := parseApkPins(world); !reflect.DeepEqual(got, want) {
		t.Errorf("parseApkPins = %v, want %v", got, want)
	}
}

func TestApkPinsHolding(t *testing.T) {
	installed := []apkPackage{
		{Name: "openssh-server-common", Origin: "openssh"},
		{Name: "openssh-keygen", Origin: "openssh"},
		{Name: "nginx", Origin: "nginx"},
		{Name: "zlib", Origin: "zlib"},
	}
	pins := []apkPin{{"openssh-server-common", "openssh-server-common><Q1x="}, {"nginx", "nginx=1.26.2-r0"}}

	// A sibling of the pinned package is left over: the pin explains it.
	got := apkPinsHolding(pins, installed, []string{"openssh-keygen"})
	if len(got) != 1 || got[0].Name != "openssh-server-common" {
		t.Errorf("sibling: got %v", got)
	}
	// The pinned package itself is left over.
	if got := apkPinsHolding(pins, installed, []string{"nginx"}); len(got) != 1 || got[0].Name != "nginx" {
		t.Errorf("self: got %v", got)
	}
	// An unrelated leftover is not blamed on a pin.
	if got := apkPinsHolding(pins, installed, []string{"zlib"}); len(got) != 0 {
		t.Errorf("unrelated: got %v", got)
	}
	if apkPinAdvice(nil) != "" {
		t.Error("advice without pins")
	}
	advice := apkPinAdvice(pins[:1])
	for _, want := range []string{"/etc/apk/world", `"openssh-server-common><Q1x="`, `to "openssh-server-common"`} {
		if !strings.Contains(advice, want) {
			t.Errorf("advice %q lacks %q", advice, want)
		}
	}
}
