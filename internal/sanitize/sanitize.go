// Package sanitize makes untrusted text safe to print in a terminal or CI log.
//
// Advisory summaries, workarounds and file contents come from third parties.
// Control characters (ANSI escapes, OSC 8 hyperlinks) and format characters
// (bidi overrides, zero-width joiners) are removed so that a crafted string
// cannot rewrite the log, hide text or forge links.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text returns s with control and format characters removed, whitespace
// collapsed to single spaces and the result cut to at most max runes.
func Text(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if r == '\t' || r == '\n' || r == '\r' || unicode.IsSpace(r) {
			space = true
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if max > 0 && utf8.RuneCountInString(out) > max {
		runes := []rune(out)
		out = strings.TrimRight(string(runes[:max-1]), " ") + "…"
	}
	return out
}
