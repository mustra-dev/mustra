package mdm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Check-in message types this slice handles. A device sends them to the
// CheckInURL as a PUT with Content-Type application/x-apple-aspen-mdm-checkin
// (apple/device-management checkin/authenticate.yaml, tokenupdate.yaml,
// checkout.yaml).
const (
	MsgAuthenticate     = "Authenticate"
	MsgTokenUpdate      = "TokenUpdate"
	MsgCheckOut         = "CheckOut"
	MsgUserAuthenticate = "UserAuthenticate"
)

// CheckinMessage is the union of the check-in messages' keys that mustra
// reads. Each message sets only its own; the rest stay zero.
type CheckinMessage struct {
	MessageType string `plist:"MessageType"`
	Topic       string `plist:"Topic"`
	UDID        string `plist:"UDID"`

	// Authenticate.
	SerialNumber string `plist:"SerialNumber"`
	Model        string `plist:"Model"`
	ModelName    string `plist:"ModelName"`
	ProductName  string `plist:"ProductName"`
	OSVersion    string `plist:"OSVersion"`
	BuildVersion string `plist:"BuildVersion"`
	DeviceName   string `plist:"DeviceName"`

	// TokenUpdate. Token is the APNs device token, PushMagic the string the
	// push must carry for the device to act on it. UnlockToken is sent by
	// supervised iOS devices only and is not kept in this slice.
	Token                 []byte `plist:"Token"`
	PushMagic             string `plist:"PushMagic"`
	AwaitingConfiguration bool   `plist:"AwaitingConfiguration"`

	// Present on the user channel (macOS per-user connections), which this
	// slice does not manage: a message carrying them is refused.
	UserID       string `plist:"UserID"`
	EnrollmentID string `plist:"EnrollmentID"`
}

// udidPattern is what a UDID may look like. Apple documents it as a string;
// Macs send an uppercase hardware UUID (8-4-4-4-12 hex) and iOS devices a
// 40-hex or 8-16 hex form. The pattern bounds it to that alphabet and a
// sane length rather than one shape, because it becomes a key and a path
// segment, not because the format is validated.
var udidPattern = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// ValidUDID reports whether s can be a device's UDID.
func ValidUDID(s string) bool { return udidPattern.MatchString(s) }

// ErrUserChannel marks a message on a macOS user channel. The server
// answers it as Apple documents for a server without user-channel support
// (UserAuthenticate: HTTP 410), and refuses the rest.
var ErrUserChannel = errors.New("user-channel messages are not supported")

// ParseCheckin decodes and checks a check-in message. It does not
// authenticate it: VerifyRequest does, and the caller then matches the
// identity to the message's UDID.
func ParseCheckin(body []byte) (*CheckinMessage, error) {
	var m CheckinMessage
	if err := Decode(body, &m); err != nil {
		return nil, err
	}
	switch m.MessageType {
	case MsgAuthenticate, MsgTokenUpdate, MsgCheckOut:
	case MsgUserAuthenticate:
		return &m, ErrUserChannel
	case "":
		return nil, errors.New("check-in message has no MessageType")
	default:
		return &m, fmt.Errorf("unsupported check-in message %q", m.MessageType)
	}
	if m.UserID != "" || m.EnrollmentID != "" {
		return &m, ErrUserChannel
	}
	if !ValidUDID(m.UDID) {
		return nil, errors.New("check-in message has no valid UDID")
	}
	if m.MessageType == MsgTokenUpdate && (len(m.Token) == 0 || m.PushMagic == "") {
		return nil, errors.New("TokenUpdate without Token and PushMagic")
	}
	return &m, nil
}

// CheckTopic says whether the message names the push topic this server
// enrolled the device under. A device enrolled under another topic is
// another MDM's (or this server's before its push certificate changed
// hands), and pushing to it would never arrive.
func (m *CheckinMessage) CheckTopic(topic string) error {
	if m.MessageType == MsgCheckOut {
		// Check-out carries the topic but is accepted regardless: a device
		// leaving should always be able to say so.
		return nil
	}
	if !strings.EqualFold(m.Topic, topic) {
		return fmt.Errorf("device topic %q is not this server's push topic", m.Topic)
	}
	return nil
}
