package mdm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Request types in this slice (apple/device-management mdm/commands/*.yaml).
const (
	CmdDeviceInformation        = "DeviceInformation"
	CmdSecurityInfo             = "SecurityInfo"
	CmdInstalledApplicationList = "InstalledApplicationList"
	CmdProfileList              = "ProfileList"
	CmdInstallProfile           = "InstallProfile"
	CmdRemoveProfile            = "RemoveProfile"
	CmdRestartDevice            = "RestartDevice"
	CmdDeviceLock               = "DeviceLock"
	CmdEraseDevice              = "EraseDevice"
)

// CommandInfo describes one request type for the server and the console.
type CommandInfo struct {
	RequestType string `json:"request_type"`
	Label       string `json:"label"`
	// Destructive commands need a second person's approval every time,
	// whatever approval policies say, and run on one device at a time.
	Destructive bool `json:"destructive"`
	// NeedsPIN commands carry a six-digit PIN the server generates when
	// the command is queued (after any approval), seals in the vault and
	// shows only to someone allowed to read recovery secrets.
	NeedsPIN bool `json:"needs_pin"`
	// Query commands only read; their responses are kept on the device.
	Query bool `json:"query"`
}

// Commands is every request type this server can send, in the order the
// console lists them.
var Commands = []CommandInfo{
	{RequestType: CmdDeviceInformation, Label: "Device information", Query: true},
	{RequestType: CmdSecurityInfo, Label: "Security information", Query: true},
	{RequestType: CmdInstalledApplicationList, Label: "Installed applications", Query: true},
	{RequestType: CmdProfileList, Label: "Installed profiles", Query: true},
	{RequestType: CmdInstallProfile, Label: "Install a profile"},
	{RequestType: CmdRemoveProfile, Label: "Remove a profile"},
	{RequestType: CmdRestartDevice, Label: "Restart"},
	{RequestType: CmdDeviceLock, Label: "Lock with a PIN", Destructive: true, NeedsPIN: true},
	{RequestType: CmdEraseDevice, Label: "Erase", Destructive: true, NeedsPIN: true},
}

// LookupCommand returns the request type's description.
func LookupCommand(requestType string) (CommandInfo, bool) {
	for _, c := range Commands {
		if c.RequestType == requestType {
			return c, true
		}
	}
	return CommandInfo{}, false
}

// DeviceInformationQueries are the keys asked of a Mac. Apple lists them
// in mdm/commands/information.device.yaml; a key the device does not know
// is left out of its answer rather than failing the command.
var DeviceInformationQueries = []string{
	"UDID", "DeviceName", "OSVersion", "BuildVersion", "SupplementalBuildVersion",
	"ModelName", "Model", "ProductName", "SerialNumber", "DeviceCapacity",
	"AvailableDeviceCapacity", "WiFiMAC", "BluetoothMAC", "EthernetMACs",
	"IsSupervised", "IsActivationLockEnabled", "IsDeviceLocatorServiceEnabled",
	"SystemIntegrityProtectionEnabled", "LocalHostName", "HostName",
	"IsAppleSilicon", "SoftwareUpdateDeviceID",
}

// CommandParams are what an operator chooses for a command. Only the
// fields a request type reads are used; Validate refuses the rest.
type CommandParams struct {
	// InstallProfile: the profile's bytes, signed or not, as uploaded.
	Profile []byte `json:"-"`
	// RemoveProfile: the PayloadIdentifier of the profile to remove.
	Identifier string `json:"identifier,omitempty"`
	// DeviceLock: shown on the lock screen.
	Message string `json:"message,omitempty"`
	// DeviceLock: shown on the lock screen as a number to call.
	PhoneNumber string `json:"phone_number,omitempty"`
	// RestartDevice: on macOS 11.3+ the user is told and may postpone.
	NotifyUser bool `json:"notify_user,omitempty"`
}

// Validate checks the parameters against the request type.
func (p CommandParams) Validate(requestType string) error {
	if _, ok := LookupCommand(requestType); !ok {
		return fmt.Errorf("unsupported command %q", requestType)
	}
	if requestType != CmdInstallProfile && len(p.Profile) > 0 {
		return errors.New("only InstallProfile takes a profile")
	}
	if requestType != CmdRemoveProfile && p.Identifier != "" {
		return errors.New("only RemoveProfile takes an identifier")
	}
	if requestType != CmdDeviceLock && (p.Message != "" || p.PhoneNumber != "") {
		return errors.New("only DeviceLock takes a message or phone number")
	}
	if requestType != CmdRestartDevice && p.NotifyUser {
		return errors.New("only RestartDevice takes notify_user")
	}
	switch requestType {
	case CmdInstallProfile:
		if len(p.Profile) == 0 {
			return errors.New("InstallProfile needs a profile")
		}
	case CmdRemoveProfile:
		if !validIdentifier(p.Identifier) {
			return errors.New("RemoveProfile needs the profile's identifier (letters, digits, '.', '-' and '_')")
		}
	case CmdDeviceLock:
		if utf8.RuneCountInString(p.Message) > 256 || strings.ContainsAny(p.Message, "\x00") {
			return errors.New("the lock message is limited to 256 characters")
		}
		for _, r := range p.PhoneNumber {
			if !strings.ContainsRune("0123456789+-() ", r) {
				return errors.New("the phone number may hold digits, spaces, '+', '-' and parentheses only")
			}
		}
		if len(p.PhoneNumber) > 32 {
			return errors.New("the phone number is too long")
		}
	}
	return nil
}

func validIdentifier(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// commandEnvelope is the command plist the server answers a device's
// connect request with (Apple: "Commands and Queries", the CommandUUID and
// Command keys).
type commandEnvelope struct {
	CommandUUID string         `plist:"CommandUUID"`
	Command     map[string]any `plist:"Command"`
}

// NewCommandUUID returns a fresh command identifier. Apple requires only
// that it be unique per device; a UUID is what it shows in its examples.
func NewCommandUUID() string { return strings.ToUpper(uuid.NewString()) }

// NewPIN returns six random digits, the form EraseDevice and DeviceLock
// take on macOS (mdm/commands/device.lock.yaml, device.erase.yaml).
func NewPIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// BuildCommand encodes the command plist a device is sent. pin is used by
// DeviceLock and EraseDevice and must be six digits for them.
func BuildCommand(commandUUID, requestType string, p CommandParams, pin string) ([]byte, error) {
	if err := p.Validate(requestType); err != nil {
		return nil, err
	}
	info, _ := LookupCommand(requestType)
	if info.NeedsPIN {
		if len(pin) != 6 || strings.Trim(pin, "0123456789") != "" {
			return nil, errors.New(requestType + " needs a six-digit PIN")
		}
	} else if pin != "" {
		return nil, errors.New(requestType + " takes no PIN")
	}
	cmd := map[string]any{"RequestType": requestType}
	switch requestType {
	case CmdDeviceInformation:
		cmd["Queries"] = DeviceInformationQueries
	case CmdInstalledApplicationList:
		// Without ManagedAppsOnly a Mac lists every app it has; this is
		// inventory, so that is the point.
	case CmdInstallProfile:
		cmd["Payload"] = p.Profile
	case CmdRemoveProfile:
		cmd["Identifier"] = p.Identifier
	case CmdRestartDevice:
		if p.NotifyUser {
			cmd["NotifyUser"] = true
		}
	case CmdDeviceLock:
		cmd["PIN"] = pin
		if p.Message != "" {
			cmd["Message"] = p.Message
		}
		if p.PhoneNumber != "" {
			cmd["PhoneNumber"] = p.PhoneNumber
		}
	case CmdEraseDevice:
		// On a Mac with Apple silicon or a T2 chip EraseDevice runs Erase
		// All Content and Settings and the PIN is not used; an older Mac
		// sets it as the Find My firmware lock, so it is always sent.
		cmd["PIN"] = pin
	}
	return Encode(commandEnvelope{CommandUUID: commandUUID, Command: cmd})
}
