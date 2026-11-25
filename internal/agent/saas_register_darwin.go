package agent

// The system-wide native messaging host directories of Chrome, Edge and
// Chromium on macOS.
func nativeHostDirs() []string {
	return []string{
		"/Library/Google/Chrome/NativeMessagingHosts",
		"/Library/Microsoft/Edge/NativeMessagingHosts",
		"/Library/Application Support/Chromium/NativeMessagingHosts",
	}
}
