// Package mdm is mustra's Apple MDM server protocol: the check-in and
// command messages a Mac exchanges with its MDM server, the device's
// identity and how its requests are authenticated, the enrollment profile,
// the per-device command queue's state machine, and the APNs push that
// wakes a device. It holds no state of its own and knows nothing of the
// database or the console: internal/server wires it to both.
//
// The message formats follow Apple's Device Management documentation
// (https://developer.apple.com/documentation/devicemanagement) and the
// machine-readable schema Apple publishes for it
// (https://github.com/apple/device-management, release branch): checkin/
// for the check-in messages, mdm/commands/ for commands and their
// responses, mdm/profiles/com.apple.mdm.yaml for the enrollment payload.
package mdm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"howett.net/plist"
)

// MaxMessageBytes bounds a check-in or command report. The largest a Mac
// sends in this slice is an InstalledApplicationList, a few hundred KB on a
// well-stocked machine; anything far past that is not a device talking.
const MaxMessageBytes = 8 << 20

// Decode reads an XML or binary property list into v. The OpenStep and
// GNUstep text formats are refused: no Apple device sends them to an MDM
// server, and a lenient parser is a larger surface on an unauthenticated
// path than this needs.
func Decode(data []byte, v any) error {
	if len(data) == 0 {
		return errors.New("empty property list")
	}
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("property list larger than %d bytes", MaxMessageBytes)
	}
	format, err := plist.Unmarshal(data, v)
	if err != nil {
		return fmt.Errorf("decoding property list: %w", err)
	}
	if format != plist.XMLFormat && format != plist.BinaryFormat {
		return fmt.Errorf("property list in %s format; only XML and binary are accepted", plist.FormatNames[format])
	}
	return nil
}

// Encode writes v as an XML property list, the format every message the
// server sends uses.
func Encode(v any) ([]byte, error) {
	return plist.MarshalIndent(v, plist.XMLFormat, "\t")
}

// JSONValue turns a decoded property list value into something
// encoding/json writes faithfully, for storing a command's response:
// data becomes base64 (cut to maxData bytes first, since a response can
// carry an icon or a certificate nobody reads in a table), dates become
// RFC 3339, and nested dictionaries and arrays are converted in turn.
func JSONValue(v any, maxData int) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = JSONValue(e, maxData)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = JSONValue(e, maxData)
		}
		return out
	case []byte:
		if maxData >= 0 && len(x) > maxData {
			return fmt.Sprintf("[%d bytes of data]", len(x))
		}
		return base64.StdEncoding.EncodeToString(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case plist.UID:
		return uint64(x)
	default:
		return x
	}
}
