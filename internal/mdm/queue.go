package mdm

import (
	"errors"
	"fmt"
)

// Report statuses a device sends to the ServerURL (Apple: "Commands and
// Queries" — Status is Acknowledged, Error, CommandFormatError, Idle or
// NotNow).
const (
	StatusIdle               = "Idle"
	StatusAcknowledged       = "Acknowledged"
	StatusError              = "Error"
	StatusCommandFormatError = "CommandFormatError"
	StatusNotNow             = "NotNow"
)

// Queue states of a command, as stored.
//
//	queued ──deliver──▶ sent ──Acknowledged──▶ acknowledged
//	  ▲                  │ ├──Error──────────▶ error
//	  │                  │ ├──CommandFormatError▶ format_error
//	  │                  │ └──NotNow─────────▶ not_now
//	  └──── Idle (next session) ◀──────────────┘ (sent: at most MaxDeliveries)
//
// cancelled and expired are set by the server, never by a report.
const (
	StateQueued       = "queued"
	StateSent         = "sent"
	StateAcknowledged = "acknowledged"
	StateError        = "error"
	StateFormatError  = "format_error"
	StateNotNow       = "not_now"
	StateCancelled    = "cancelled"
	StateExpired      = "expired"
)

// MaxDeliveries bounds how often a command sent without an answer is sent
// again. A Mac told to restart may restart before its acknowledgement
// leaves; resending without a limit would restart it on every check-in.
const MaxDeliveries = 3

// Final reports whether a state is the end of a command's life.
func Final(state string) bool {
	switch state {
	case StateAcknowledged, StateError, StateFormatError, StateCancelled, StateExpired:
		return true
	}
	return false
}

// Pending reports whether a command still waits to reach the device.
func Pending(state string) bool {
	return state == StateQueued || state == StateSent || state == StateNotNow
}

// ErrAlreadyFinal is returned for a report about a command that has
// already finished: a repeat of a report the server already took, which
// must not overwrite the first.
var ErrAlreadyFinal = errors.New("command already finished")

// ReportTransition is the state a command moves to when the device
// reports status about it. A report may arrive for a command the server
// has since cancelled: the device ran it anyway, so the outcome is taken
// (a cancel can only stop what has not been delivered).
func ReportTransition(current, status string) (string, error) {
	switch current {
	case StateAcknowledged, StateError, StateFormatError, StateExpired:
		return current, ErrAlreadyFinal
	case StateQueued, StateSent, StateNotNow, StateCancelled:
	default:
		return current, fmt.Errorf("unknown command state %q", current)
	}
	switch status {
	case StatusAcknowledged:
		return StateAcknowledged, nil
	case StatusError:
		return StateError, nil
	case StatusCommandFormatError:
		return StateFormatError, nil
	case StatusNotNow:
		if current == StateCancelled {
			return StateCancelled, nil
		}
		return StateNotNow, nil
	}
	return current, fmt.Errorf("unknown report status %q", status)
}

// IdleTransition is what happens to a command when its device starts a new
// session (reports Idle). A command the device deferred (NotNow) is
// offered again. One delivered without any answer is offered again until
// it has been delivered MaxDeliveries times, then fails rather than loop.
// ok is false when the state is left as it is.
func IdleTransition(current string, deliveries int) (next string, ok bool) {
	switch current {
	case StateNotNow:
		return StateQueued, true
	case StateSent:
		if deliveries >= MaxDeliveries {
			return StateError, true
		}
		return StateQueued, true
	}
	return current, false
}

// CommandReport is what a device sends to the ServerURL: the status of the
// last command it was given, with that command's response keys, or Idle
// when it is ready for the next one.
type CommandReport struct {
	UDID         string           `plist:"UDID"`
	Status       string           `plist:"Status"`
	CommandUUID  string           `plist:"CommandUUID"`
	ErrorChain   []ErrorChainItem `plist:"ErrorChain"`
	UserID       string           `plist:"UserID"`
	EnrollmentID string           `plist:"EnrollmentID"`
	// Raw is the whole report, for the response keys each request type
	// adds (QueryResponses, SecurityInfo, InstalledApplicationList,
	// ProfileList).
	Raw map[string]any `plist:"-"`
}

// ErrorChainItem is one entry of a failed command's ErrorChain.
type ErrorChainItem struct {
	ErrorCode            int    `plist:"ErrorCode" json:"code"`
	ErrorDomain          string `plist:"ErrorDomain" json:"domain"`
	LocalizedDescription string `plist:"LocalizedDescription" json:"description"`
	USEnglishDescription string `plist:"USEnglishDescription" json:"us_english,omitempty"`
}

// ParseReport decodes and checks a command report.
func ParseReport(body []byte) (*CommandReport, error) {
	var r CommandReport
	if err := Decode(body, &r); err != nil {
		return nil, err
	}
	if err := Decode(body, &r.Raw); err != nil {
		return nil, err
	}
	if r.UserID != "" || r.EnrollmentID != "" {
		return &r, ErrUserChannel
	}
	if !ValidUDID(r.UDID) {
		return nil, errors.New("report has no valid UDID")
	}
	switch r.Status {
	case StatusIdle:
		return &r, nil
	case StatusAcknowledged, StatusError, StatusCommandFormatError, StatusNotNow:
		if r.CommandUUID == "" || len(r.CommandUUID) > 128 {
			return nil, errors.New("report has no CommandUUID")
		}
		return &r, nil
	}
	return nil, fmt.Errorf("unknown report status %q", r.Status)
}

// ResultKey is the key a request type's answer arrives under in an
// Acknowledged report, or "" for a command that answers nothing.
func ResultKey(requestType string) string {
	switch requestType {
	case CmdDeviceInformation:
		return "QueryResponses"
	case CmdSecurityInfo:
		return "SecurityInfo"
	case CmdInstalledApplicationList:
		return "InstalledApplicationList"
	case CmdProfileList:
		return "ProfileList"
	}
	return ""
}
