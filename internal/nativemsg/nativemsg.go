// Package nativemsg implements Chrome's native messaging framing: each
// message is a 32-bit length in the machine's native byte order followed
// by that many bytes of UTF-8 JSON, on the host's stdin and stdout.
//
// The browser is the only peer that should ever be on the other end, but
// the host runs as the signed-in user and anything that user runs can
// start it too, so a length is never trusted to allocate: Read refuses a
// message over its cap before reading a byte of the body.
package nativemsg

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxHostToBrowser is Chrome's own limit on a message from the host.
const MaxHostToBrowser = 1 << 20

var (
	// ErrTooLarge is a declared length over the reader's cap.
	ErrTooLarge = errors.New("native message exceeds the size limit")
	// ErrTruncated is a stream that ended inside a length or a body.
	ErrTruncated = errors.New("native message truncated")
	// ErrEmpty is a zero-length message, which is not JSON.
	ErrEmpty = errors.New("empty native message")
)

// Read returns the next message's body. It returns io.EOF only when the
// stream ends cleanly between messages, which is how the browser says it
// is done.
func Read(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	n, err := io.ReadFull(r, hdr[:])
	if err == io.EOF && n == 0 {
		return nil, io.EOF
	}
	if err != nil {
		return nil, ErrTruncated
	}
	size := binary.NativeEndian.Uint32(hdr[:])
	if size == 0 {
		return nil, ErrEmpty
	}
	if uint64(size) > uint64(max) {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrTooLarge, size, max)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrTruncated
	}
	return body, nil
}

// Write sends one message.
func Write(w io.Writer, body []byte) error {
	if len(body) == 0 {
		return ErrEmpty
	}
	if len(body) > MaxHostToBrowser {
		return fmt.Errorf("%w: %d bytes, at most %d", ErrTooLarge, len(body), MaxHostToBrowser)
	}
	buf := make([]byte, 4+len(body))
	binary.NativeEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

// WriteJSON encodes v and sends it.
func WriteJSON(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return Write(w, body)
}
