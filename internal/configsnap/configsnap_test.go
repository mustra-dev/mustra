package configsnap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func deployDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	must := func(rel, content string) {
		p := filepath.Join(d, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must(".env", "MUSTRA_CREDENTIAL_ENCRYPTION_KEY=secret\n")
	must("version.env", "MUSTRA_IMAGE_TAG=1.5.0\n")
	must("nats/certs/ca.key", "ca private key")
	must("nats/certs/ca.crt", "ca cert")
	must("cloudflared/config.yml", "the tracked template, not wanted")
	must("docker-compose.yml", "tracked, not wanted")
	// A link out of the deploy directory must never be followed.
	os.Symlink("/etc/passwd", filepath.Join(d, "nats/certs/escape.pem"))
	return d
}

func decrypt(t *testing.T, path string, id age.Identity) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[hdr.Name] = string(b)
	}
	return out
}

func TestSnapshotRoundTrip(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	out := t.TempDir()
	if err := Snapshot(deployDir(t), out, id.Recipient().String()+", "+other.Recipient().String(), time.Now()); err != nil {
		t.Fatal(err)
	}
	// Either key opens it.
	for _, k := range []age.Identity{id, other} {
		files := decrypt(t, filepath.Join(out, BlobName), k)
		if files[".env"] != "MUSTRA_CREDENTIAL_ENCRYPTION_KEY=secret\n" || files["nats/certs/ca.key"] != "ca private key" || files["version.env"] == "" {
			t.Fatalf("got %v", files)
		}
		for _, unwanted := range []string{"cloudflared/config.yml", "docker-compose.yml", "nats/certs/escape.pem"} {
			if _, ok := files[unwanted]; ok {
				t.Errorf("%s is in the snapshot", unwanted)
			}
		}
	}
	// The secret never appears readable on disk.
	raw, _ := os.ReadFile(filepath.Join(out, BlobName))
	if bytes.Contains(raw, []byte("secret")) {
		t.Error("the snapshot holds the key in the clear")
	}
	st, ok := ReadStatus(out)
	if !ok || st.Error != "" || len(st.Recipients) != 2 || !slices.Contains(st.Files, ".env") {
		t.Errorf("status %+v", st)
	}
	statusRaw, _ := os.ReadFile(filepath.Join(out, StatusName))
	if strings.Contains(string(statusRaw), "secret") || strings.Contains(string(statusRaw), "ca private") {
		t.Error("the status holds file contents")
	}
	if info, _ := os.Stat(out); info.Mode().Perm() != 0o700 {
		t.Errorf("snapshot directory is %v", info.Mode().Perm())
	}
	if rc, size, _, err := Open(out); err != nil || size == 0 {
		t.Errorf("open: %v", err)
	} else {
		rc.Close()
	}
	// A key that is not a recipient cannot open it.
	stranger, _ := age.GenerateX25519Identity()
	f, _ := os.Open(filepath.Join(out, BlobName))
	defer f.Close()
	if _, err := age.Decrypt(f, stranger); err == nil {
		t.Error("a stranger's key opened the snapshot")
	}
}

func TestSnapshotOffRemovesTheOldOne(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	out, dir := t.TempDir(), deployDir(t)
	if err := Snapshot(dir, out, id.Recipient().String(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Snapshot(dir, out, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, BlobName)); !os.IsNotExist(err) {
		t.Error("turning it off left the snapshot")
	}
	if st, _ := ReadStatus(out); !st.Disabled {
		t.Errorf("status %+v", st)
	}
	if _, _, _, err := Open(out); err == nil {
		t.Error("opened a disabled snapshot")
	}
}

func TestSnapshotRefusesABadKeyAndSaysSo(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	out, dir := t.TempDir(), deployDir(t)
	Snapshot(dir, out, id.Recipient().String(), time.Now())
	err := Snapshot(dir, out, "AGE-SECRET-KEY-1NOTAPUBLICKEY", time.Now())
	if err == nil {
		t.Fatal("accepted a private key as a recipient")
	}
	st, _ := ReadStatus(out)
	if !strings.Contains(st.Error, "not an age public key") {
		t.Errorf("status %+v", st)
	}
	// A stale snapshot must not be mistaken for a current one.
	if _, err := os.Stat(filepath.Join(out, BlobName)); !os.IsNotExist(err) {
		t.Error("kept the previous snapshot after a failure")
	}
}

func TestSnapshotWithoutEnvFails(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	if err := Snapshot(t.TempDir(), t.TempDir(), id.Recipient().String(), time.Now()); err == nil {
		t.Error("made a snapshot of a directory with no .env")
	}
}
