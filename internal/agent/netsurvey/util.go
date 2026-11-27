package netsurvey

import (
	"strings"
	"unicode"
)

// cleanString makes a device-supplied string safe to carry: valid UTF-8,
// no control characters, no NUL padding, bounded.
func cleanString(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			if r == '\n' || r == '\t' || r == '\r' {
				return ' '
			}
			return -1
		}
		return r
	}, s)
	return truncate(strings.TrimSpace(s), 256)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8Start(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return strings.ToValidUTF8(s, "")
}

func utf8Start(b byte) bool { return b < 0x80 || b >= 0xC0 }

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
