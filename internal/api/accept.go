package api

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ferhatcil/cdgate/internal/model"
)

// Reasons for a package the CyberDetails API would refuse. One refused item
// makes the whole /sca/query request a 422, so such a package is listed as
// not checked instead of being sent (the rest of the scan still runs).
const (
	NameNotAccepted    = "package name has characters the CyberDetails API does not accept (package registries do not use them); not checked"
	VersionNotAccepted = "package version is empty, too long or has characters the CyberDetails API does not accept; not checked"
)

// Rejected mirrors the API's per-package checks (models/sca.py
// ScaPackageIn field lengths and ScaQueryRequest._paketler with
// utils/sca_key.ad_anahtari): it returns "" when the API accepts the package.
// Shared fixture: cyberdetails.sca/tests/fixtures/api_accepts.json, generated
// from the API model.
func Rejected(p model.Package) string {
	if !nameAccepted(p.Name) {
		return NameNotAccepted
	}
	if !versionAccepted(p.Version) {
		return VersionNotAccepted
	}
	if strings.HasPrefix(p.Ecosystem, "RapidFort:") {
		for _, b := range p.Binaries {
			if !nameAccepted(b) {
				return NameNotAccepted
			}
		}
	}
	return ""
}

// pyStrip is Python's str.strip(): str.isspace is unicode.IsSpace plus
// U+001C..U+001F (bidirectional class B/S), which Go does not count as space.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
}

// nameAccepted: 1-214 characters as sent (pydantic max_length counts code
// points; the API's second, post-strip limit of 214 cannot be exceeded
// then), and after strip a non-empty run of Unicode letters, numbers or marks
// (categories L, N, M) or "@/._:+~-".
func nameAccepted(n string) bool {
	if c := utf8.RuneCountInString(n); c < 1 || c > 214 || !utf8.ValidString(n) {
		return false
	}
	t := pyStrip(n)
	if t == "" {
		return false
	}
	for _, r := range t {
		if !(unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || strings.ContainsRune("@/._:+~-", r)) {
			return false
		}
	}
	return true
}

// versionAccepted: 1-100 characters as sent, not empty after strip, and no
// character of category C or Z, where C includes unassigned code points
// (Python's "Cn"). Whether Go's unicode.C covers unassigned code points
// depends on the Go release (it does not in Go 1.22, found by CI), so they
// are checked explicitly. Known limit: the Unicode version follows the Go
// toolchain (15.0 in Go 1.22, like the API's Python; newer in later
// releases); a character assigned after 15.0 can be accepted here and
// refused there, which fails the request (exit 2), never passes it.
func versionAccepted(v string) bool {
	if c := utf8.RuneCountInString(v); c < 1 || c > 100 || !utf8.ValidString(v) {
		return false
	}
	t := pyStrip(v)
	if t == "" {
		return false
	}
	for _, r := range t {
		if unicode.In(r, unicode.C, unicode.Z) || !assigned(r) {
			return false
		}
	}
	return true
}

// assigned reports whether r has a general category other than "unassigned"
// in this toolchain's Unicode tables.
func assigned(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
		unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}
