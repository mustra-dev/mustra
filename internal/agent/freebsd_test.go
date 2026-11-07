package agent

import "testing"

// The shape pkg version -vRl '<' prints on FreeBSD 14, taken from a real
// run, plus a package name with dashes and a version with a comma (epoch).
func TestParsePkgVersion(t *testing.T) {
	out := []byte(`Updating FreeBSD repository catalogue...
FreeBSD repository is up to date.
All repositories are up to date.
jq-1.0                             <   needs updating (remote has 1.8.2)
py311-cryptography-42.0.8_3,1      <   needs updating (remote has 44.0.0,1)
curl-8.10.1                        =   up-to-date with remote
`)
	got := parsePkgVersion(out)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "jq" || got[0].CurrentVersion != "1.0" || got[0].NewVersion != "1.8.2" {
		t.Errorf("jq: %+v", got[0])
	}
	if got[1].Name != "py311-cryptography" || got[1].CurrentVersion != "42.0.8_3,1" || got[1].NewVersion != "44.0.0,1" {
		t.Errorf("dashes: %+v", got[1])
	}
	if got := parsePkgVersion(nil); got == nil || len(got) != 0 {
		t.Errorf("nothing pending must be an empty list, got %v", got)
	}
}
