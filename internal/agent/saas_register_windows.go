package agent

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// On Windows a browser finds a native messaging host through a registry
// key named after it, whose default value is the path of the manifest.
// HKLM, so it is there for every user of the machine; the manifest sits
// beside the agent binary, where only administrators can change it.

var nativeHostRegistryKeys = []string{
	`SOFTWARE\Google\Chrome\NativeMessagingHosts\` + nativeHostName,
	`SOFTWARE\Microsoft\Edge\NativeMessagingHosts\` + nativeHostName,
	`SOFTWARE\Chromium\NativeMessagingHosts\` + nativeHostName,
}

func nativeHostManifestPath(exe string) string {
	return filepath.Join(filepath.Dir(exe), nativeHostName+".json")
}

func registerNativeHost(exe string, manifest []byte) error {
	path := nativeHostManifestPath(exe)
	if err := writeFileAtomic(path, manifest, 0o644); err != nil {
		return err
	}
	var errs []error
	for _, k := range nativeHostRegistryKeys {
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, k, registry.SET_VALUE)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := key.SetStringValue("", path); err != nil {
			errs = append(errs, err)
		}
		key.Close()
	}
	return errors.Join(errs...)
}

func unregisterNativeHost(exe string) error {
	var errs []error
	for _, k := range nativeHostRegistryKeys {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, k); err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(nativeHostManifestPath(exe)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
