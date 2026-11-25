package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustra-dev/mustra/internal/saasmon"
)

// The real extension packs into a package the server accepts, with the
// update URL written in and the tests left out, and the key file is
// created private and never overwritten.
func TestPackTheExtension(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	if err := writeKey(keyPath); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(keyPath); os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	if err := writeKey(keyPath); err == nil {
		t.Fatal("an existing key was overwritten")
	}
	key, err := readKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	archive, ver, err := zipExtension(filepath.Join("..", "..", "extension", "saas-monitor"), "https://console.example.com/saas-extension/update.xml", "1.0.7")
	if err != nil {
		t.Fatal(err)
	}
	if ver != "1.0.7" {
		t.Fatalf("version %q", ver)
	}
	zr, _ := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		if f.Name == "manifest.json" {
			rc, _ := f.Open()
			var m map[string]any
			_ = json.NewDecoder(rc).Decode(&m)
			rc.Close()
			if m["update_url"] != "https://console.example.com/saas-extension/update.xml" || m["version"] != "1.0.7" {
				t.Fatalf("manifest %v", m)
			}
		}
	}
	for _, want := range []string{"manifest.json", "background.js", "content.js", "lib.js"} {
		if !names[want] {
			t.Errorf("%s missing from the package", want)
		}
	}
	for name := range names {
		if filepath.Dir(name) == "test" || name == "README.md" {
			t.Errorf("%s should not be packed", name)
		}
	}
	crx, id, err := saasmon.BuildCRX(archive, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := saasmon.ParseCRX(crx)
	if err != nil || info.ID != id || info.Version != "1.0.7" {
		t.Fatalf("%+v %v", info, err)
	}
	// Same key, same ID: a later version installs over the earlier one.
	again, _, _ := zipExtension(filepath.Join("..", "..", "extension", "saas-monitor"), "", "1.0.8")
	_, id2, _ := saasmon.BuildCRX(again, key)
	if id2 != id {
		t.Fatal("the ID changed between versions packed with one key")
	}
	if _, _, err := zipExtension(filepath.Join("..", "..", "extension", "saas-monitor"), "http://insecure.example/u.xml", ""); err == nil {
		t.Fatal("a plain-http update URL was accepted")
	}
}
