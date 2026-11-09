// Package configsnap keeps an encrypted copy of what a restore needs that the
// database does not hold: the deployment's .env (the credential encryption
// key, the update signing key, the bus passwords), version.env, the NATS
// certificates and the Cloudflare Tunnel credentials.
//
// It is encrypted to age public keys (https://age-encryption.org) that the
// operator sets in .env; the private keys never reach this host. A backup
// that carried those secrets readable would hand whoever holds the archive
// every stored credential, which is why backups left them out until now.
//
// The snapshot runs in the root one-shot container that starts before the
// server (deploy/docker-compose.yml, data-owner), because those files are
// root's and mode 600 and the server is not root. The server only reads the
// encrypted result and puts it in each backup.
package configsnap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	// BlobName and StatusName are the files in the snapshot directory.
	BlobName   = "config.tar.age"
	StatusName = "status.json"

	maxFile  = 1 << 20  // no configuration file is a megabyte
	maxTotal = 16 << 20 // nor are all of them together
	serverID = 65532    // the uid the server runs as (deploy/Dockerfile.server)
)

// included are the paths under the deploy directory a restore needs: single
// files, or directories whose regular files are all taken.
var included = []string{
	".env",
	"version.env",
	"nats/certs",
	"cloudflared/config.local.yml",
	"cloudflared/creds.json",
}

// Status says what the last snapshot holds, without any of its contents. It
// is written beside the snapshot for the server to show and to record.
type Status struct {
	CreatedAt  time.Time `json:"created_at"`
	Recipients []string  `json:"recipients,omitempty"` // age public keys, which are not secret
	Files      []string  `json:"files,omitempty"`
	Error      string    `json:"error,omitempty"`
	Disabled   bool      `json:"disabled,omitempty"`
}

// ParseRecipients reads age public keys separated by commas, spaces or lines.
func ParseRecipients(text string) ([]age.Recipient, []string, error) {
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
	var recipients []age.Recipient
	for _, f := range fields {
		r, err := age.ParseX25519Recipient(f)
		if err != nil {
			return nil, nil, fmt.Errorf("%q is not an age public key (age1…): %w", f, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, fields, nil
}

// Snapshot encrypts the deploy directory's configuration to the recipients
// into outDir. With no recipients it removes any earlier snapshot, so turning
// the feature off leaves nothing behind. Errors are also written to the status
// file, because nobody watches the one-shot container's output.
func Snapshot(deployDir, outDir, recipientsText string, now time.Time) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	st := Status{CreatedAt: now.UTC()}
	err := snapshot(deployDir, outDir, recipientsText, &st)
	if err != nil {
		st.Error = err.Error()
		_ = os.Remove(filepath.Join(outDir, BlobName))
	}
	raw, _ := json.MarshalIndent(st, "", "  ")
	if werr := writeOwned(filepath.Join(outDir, StatusName), raw); werr != nil && err == nil {
		err = werr
	}
	// Docker creates a volume's directory world-readable; nobody but the
	// server has any business listing it.
	_ = os.Chmod(outDir, 0o700)
	if os.Geteuid() == 0 {
		_ = os.Chown(outDir, serverID, serverID)
	}
	return err
}

func snapshot(deployDir, outDir, recipientsText string, st *Status) error {
	if strings.TrimSpace(recipientsText) == "" {
		st.Disabled = true
		return removeIfExists(filepath.Join(outDir, BlobName))
	}
	recipients, names, err := ParseRecipients(recipientsText)
	if err != nil {
		return err
	}
	st.Recipients = names
	archive, files, err := collect(deployDir)
	if err != nil {
		return err
	}
	if !slices.Contains(files, ".env") {
		return errors.New("no .env in the deploy directory: nothing worth keeping was found")
	}
	st.Files = files
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(archive); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return writeOwned(filepath.Join(outDir, BlobName), enc.Bytes())
}

// collect makes a gzipped tar of the included paths that exist, with their
// paths relative to the deploy directory, so it extracts straight into one.
func collect(deployDir string) ([]byte, []string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	var files []string
	total := 0
	add := func(rel string, info fs.FileInfo) error {
		if !info.Mode().IsRegular() {
			return nil // never follow a link out of the deploy directory
		}
		if info.Size() > maxFile {
			return fmt.Errorf("%s is %d bytes, more than a configuration file should be", rel, info.Size())
		}
		data, err := os.ReadFile(filepath.Join(deployDir, rel))
		if err != nil {
			return err
		}
		if total += len(data); total > maxTotal {
			return errors.New("the configuration files add up to more than 16 MB")
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: int64(info.Mode().Perm()), Size: int64(len(data)), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	}
	for _, rel := range included {
		info, err := os.Lstat(filepath.Join(deployDir, rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			if err := add(rel, info); err != nil {
				return nil, nil, err
			}
			continue
		}
		entries, err := os.ReadDir(filepath.Join(deployDir, rel))
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				return nil, nil, err
			}
			if err := add(filepath.Join(rel, e.Name()), info); err != nil {
				return nil, nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), files, nil
}

// writeOwned writes a file the server can read and nobody else can, atomically.
func writeOwned(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	// Only root can give a file away; under test the owner stays as it is.
	if os.Geteuid() == 0 {
		if err := os.Chown(tmp, serverID, serverID); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ReadStatus reads the status of the snapshot in dir; ok is false when there
// has never been one.
func ReadStatus(dir string) (Status, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, StatusName))
	if err != nil {
		return Status{}, false
	}
	var st Status
	if json.Unmarshal(raw, &st) != nil {
		return Status{}, false
	}
	return st, true
}

// Open returns the encrypted snapshot in dir, when the last one succeeded.
func Open(dir string) (io.ReadCloser, int64, Status, error) {
	st, ok := ReadStatus(dir)
	if !ok || st.Disabled || st.Error != "" {
		return nil, 0, st, fs.ErrNotExist
	}
	f, err := os.Open(filepath.Join(dir, BlobName))
	if err != nil {
		return nil, 0, st, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, st, err
	}
	return f, info.Size(), st, nil
}
