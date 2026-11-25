//go:build linux || darwin

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeHostRegistrationFiles(t *testing.T) {
	root := t.TempDir()
	dirs := []string{filepath.Join(root, "chrome", "native-messaging-hosts"), filepath.Join(root, "edge", "native-messaging-hosts")}
	if err := registerNativeHostIn(dirs, []byte(`{"name":"x"}`)); err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		fi, err := os.Stat(filepath.Join(d, nativeHostName+".json"))
		if err != nil {
			t.Fatal(err)
		}
		// Browsers run as the user and must be able to read it.
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
	if err := unregisterNativeHostIn(dirs); err != nil {
		t.Fatal(err)
	}
	if err := unregisterNativeHostIn(dirs); err != nil {
		t.Fatalf("removing twice must be harmless: %v", err)
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, nativeHostName+".json")); !os.IsNotExist(err) {
			t.Fatal("manifest left behind")
		}
	}
}
