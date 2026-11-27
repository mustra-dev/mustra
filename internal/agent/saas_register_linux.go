package agent

// The system-wide native messaging host directories of Chrome, Chromium
// and Edge on Linux.
func nativeHostDirs() []string {
	return []string{
		"/etc/opt/chrome/native-messaging-hosts",
		"/etc/chromium/native-messaging-hosts",
		"/etc/opt/edge/native-messaging-hosts",
	}
}
