//go:build linux || darwin

package agent

import (
	"errors"
	"os"
	"path/filepath"
)

// On Linux and macOS a browser finds a native messaging host by a JSON
// file named after it in a system-wide directory of its own. Writing the
// file is all registration is.

// registerNativeHost writes the manifest into every browser's directory.
// A browser that is not installed simply never reads its copy.
func registerNativeHost(_ string, manifest []byte) error {
	return registerNativeHostIn(nativeHostDirs(), manifest)
}

func unregisterNativeHost(_ string) error {
	return unregisterNativeHostIn(nativeHostDirs())
}

func registerNativeHostIn(dirs []string, manifest []byte) error {
	var errs []error
	for _, d := range dirs {
		if err := writeFileAtomic(filepath.Join(d, nativeHostName+".json"), manifest, 0o644); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func unregisterNativeHostIn(dirs []string) error {
	var errs []error
	for _, d := range dirs {
		if err := os.Remove(filepath.Join(d, nativeHostName+".json")); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
