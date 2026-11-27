// Command saas-extension-pack packs the SaaS monitoring browser extension
// (extension/saas-monitor) into a signed .crx for mustra to serve, and a
// .zip of the same files.
//
// The extension's ID is derived from the signing key, so every version must
// be packed with the same key: generate it once with -genkey and keep it
// with your other secrets. It never goes to the server or into git (the
// repository ignores *.pem).
//
//	go run ./cmd/saas-extension-pack -genkey saas-monitor.pem
//	go run ./cmd/saas-extension-pack -key saas-monitor.pem \
//	    -update-url https://console.example.com/saas-extension/update.xml \
//	    -out dist extension/saas-monitor
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/saasmon"
)

func main() {
	genkey := flag.String("genkey", "", "write a new 2048-bit RSA signing key to this file and exit")
	keyPath := flag.String("key", "", "the signing key (PEM, PKCS#1 or PKCS#8)")
	outDir := flag.String("out", "dist", "directory to write the .crx and .zip to")
	updateURL := flag.String("update-url", "", "the update manifest URL to write into the extension (https://<console>/saas-extension/update.xml)")
	version := flag.String("version", "", "override the manifest's version")
	flag.Parse()

	if *genkey != "" {
		if err := writeKey(*genkey); err != nil {
			fail(err)
		}
		return
	}
	if *keyPath == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: saas-extension-pack -genkey key.pem | -key key.pem [-update-url URL] [-version V] [-out dir] <extension dir>")
		os.Exit(2)
	}
	key, err := readKey(*keyPath)
	if err != nil {
		fail(err)
	}
	archive, ver, err := zipExtension(flag.Arg(0), *updateURL, *version)
	if err != nil {
		fail(err)
	}
	crx, id, err := saasmon.BuildCRX(archive, key)
	if err != nil {
		fail(err)
	}
	// Check the result the way the server will before anyone uploads it.
	if _, err := saasmon.ParseCRX(crx); err != nil {
		fail(fmt.Errorf("the packed extension does not verify: %w", err))
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}
	base := filepath.Join(*outDir, "mustra-saas-monitor-"+ver)
	if err := os.WriteFile(base+".crx", crx, 0o644); err != nil {
		fail(err)
	}
	if err := os.WriteFile(base+".zip", archive, 0o644); err != nil {
		fail(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	fmt.Printf("extension id: %s\nversion:      %s\npackage:      %s.crx\narchive:      %s.zip\nmanifest key: %s\n",
		id, ver, base, base, base64.StdEncoding.EncodeToString(pub))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "saas-extension-pack:", err)
	os.Exit(1)
}

func writeKey(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// O_EXCL: overwriting a key changes the extension's ID for good.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	fmt.Printf("wrote %s (keep it secret and backed up)\nextension id: %s\n", path, saasmon.ExtensionID(pub))
	return nil
}

func readKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("the key file is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the key is neither PKCS#1 nor PKCS#8 RSA: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the key is not an RSA key")
	}
	return rk, nil
}

// packed is what goes into the package: the manifest and the scripts. The
// tests, the README and anything hidden stay out.
func packed(rel string) bool {
	if strings.HasPrefix(filepath.Base(rel), ".") || strings.HasPrefix(rel, "test"+string(filepath.Separator)) || rel == "test" {
		return false
	}
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".js", ".json", ".png", ".svg", ".html", ".css":
		return true
	}
	return false
}

// zipExtension builds a deterministic zip of dir, with the manifest's
// update_url (and version) set.
func zipExtension(dir, updateURL, version string) ([]byte, string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || rel == "test" || d.Name() == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		if packed(rel) {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	sort.Strings(files)
	var manifest map[string]any
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, "", fmt.Errorf("no manifest.json in %s", dir)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, "", fmt.Errorf("manifest.json: %w", err)
	}
	if updateURL != "" {
		u, err := url.Parse(updateURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, "", errors.New("-update-url must be an https URL")
		}
		manifest["update_url"] = updateURL
	}
	if version != "" {
		if !saasmon.ValidVersion(version) {
			return nil, "", fmt.Errorf("%q is not an extension version (1 to 4 dot-separated numbers)", version)
		}
		manifest["version"] = version
	}
	ver, _ := manifest["version"].(string)
	if !saasmon.ValidVersion(ver) {
		return nil, "", fmt.Errorf("manifest version %q is not an extension version", ver)
	}
	mraw, _ := json.MarshalIndent(manifest, "", "  ")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, rel := range files {
		data := mraw
		if rel != "manifest.json" {
			if data, err = os.ReadFile(filepath.Join(dir, rel)); err != nil {
				return nil, "", err
			}
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), ver, nil
}
