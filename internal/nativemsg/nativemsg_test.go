package nativemsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func frame(body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.NativeEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}

func TestReadWriteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, []byte(`{"type":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&buf, map[string]int{"n": 2}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 1024)
	if err != nil || string(got) != `{"type":"hello"}` {
		t.Fatalf("first message %q, %v", got, err)
	}
	got, err = Read(&buf, 1024)
	if err != nil || string(got) != `{"n":2}` {
		t.Fatalf("second message %q, %v", got, err)
	}
	if _, err := Read(&buf, 1024); !errors.Is(err, io.EOF) {
		t.Fatalf("clean end should be io.EOF, got %v", err)
	}
}

// The length prefix is in the machine's byte order, which is what Chrome
// writes; on every platform the agent ships for, that is little-endian.
func TestLengthIsNativeOrder(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, []byte("{}"))
	if got := binary.NativeEndian.Uint32(buf.Bytes()[:4]); got != 2 {
		t.Fatalf("length %d", got)
	}
}

func TestReadRefusesOversizeBeforeAllocating(t *testing.T) {
	// A declared 4 GB body with nothing behind it: refused on the length
	// alone, without trying to read (or allocate) the body.
	hdr := make([]byte, 4)
	binary.NativeEndian.PutUint32(hdr, 0xFFFFFFFF)
	if _, err := Read(bytes.NewReader(hdr), 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, err := Read(bytes.NewReader(frame(make([]byte, 101))), 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over the cap: want ErrTooLarge, got %v", err)
	}
	if _, err := Read(bytes.NewReader(frame(make([]byte, 100))), 100); err != nil {
		t.Fatalf("exactly the cap should be read: %v", err)
	}
}

func TestReadMalformed(t *testing.T) {
	cases := map[string][]byte{
		"partial length": {1, 0},
		"short body":     append(frame([]byte("{}"))[:4], '{'),
		"zero length":    frame(nil),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(in), 1024)
			if err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("want a framing error, got %v", err)
			}
		})
	}
}

func TestWriteRefusesWhatChromeWouldNot(t *testing.T) {
	if err := Write(io.Discard, make([]byte, MaxHostToBrowser+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if err := Write(io.Discard, nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
}
