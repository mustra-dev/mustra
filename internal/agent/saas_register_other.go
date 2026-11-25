//go:build !linux && !darwin && !windows

package agent

import "errors"

// No supported browser reads native messaging hosts on this platform the
// way the agent registers them, so SaaS monitoring is not available here.
var errNativeHostUnsupported = errors.New("SaaS monitoring's native messaging host is not supported on this platform")

func registerNativeHost(string, []byte) error { return errNativeHostUnsupported }

func unregisterNativeHost(string) error { return nil }
