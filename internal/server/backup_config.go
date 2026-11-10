package server

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/mustra-dev/mustra/internal/configsnap"
)

// The deployment's configuration in a backup: the encrypted snapshot the
// data-owner service makes at each start (internal/configsnap). The server
// never sees it decrypted; it copies the ciphertext into the archive.

const backupConfigName = "config.tar.age"

func configSnapshotDir() string {
	if d := os.Getenv("MUSTRA_CONFIG_SNAPSHOT_DIR"); d != "" {
		return d
	}
	return "/var/lib/mustra/config-snapshot"
}

// addConfigSnapshot adds the snapshot when there is a good one; no snapshot
// is not an error, since it is opt-in.
func addConfigSnapshot(tw *tar.Writer) (string, *time.Time, error) {
	rc, size, st, err := configsnap.Open(configSnapshotDir())
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	defer rc.Close()
	if err := tw.WriteHeader(&tar.Header{Name: backupConfigName, Mode: 0o600, Size: size, ModTime: st.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return "", nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(tw, io.TeeReader(io.LimitReader(rc, size), h)); err != nil {
		return "", nil, err
	}
	taken := st.CreatedAt
	return hex.EncodeToString(h.Sum(nil)), &taken, nil
}

// backupConfigStatus is the configuration snapshot as the backup page shows
// it: whether backups carry the configuration, and why not when they don't.
type backupConfigStatus struct {
	Included   bool       `json:"included"`
	Recipients []string   `json:"recipients,omitempty"`
	Files      []string   `json:"files,omitempty"`
	TakenAt    *time.Time `json:"taken_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

func currentConfigStatus() backupConfigStatus {
	st, ok := configsnap.ReadStatus(configSnapshotDir())
	if !ok || st.Disabled {
		return backupConfigStatus{}
	}
	out := backupConfigStatus{Recipients: st.Recipients, Error: st.Error}
	if st.Error == "" {
		out.Included, out.Files = true, st.Files
		t := st.CreatedAt
		out.TakenAt = &t
	}
	return out
}
