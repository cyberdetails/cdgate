package gate

// Version comparison for the fix plan (port of cd_sca_gate.py). Two versions
// that cannot be compared give ok=false and the plan shows the package as
// uncertain with its candidates: "one of these, check" is better than a wrong
// "upgrade to X".

import (
	"regexp"
	"strings"
)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func asciiNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// cmpNumber compares two ASCII digit strings by value, of any length
// (Python int has no size limit; a version component can exceed int64).
func cmpNumber(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	switch {
	case len(a) != len(b):
		if len(a) < len(b) {
			return -1
		}
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// debOrder and verrevcmp are dpkg's lib/dpkg/version.c, byte by byte, in the
// C locale (ASCII digits and letters only).
func debOrder(a string, i int) int {
	if i >= len(a) || isDigit(a[i]) {
		return 0
	}
	c := a[i]
	switch {
	case c == '~':
		return -1
	case isAlpha(c):
		return int(c)
	}
	return int(c) + 256
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(a, i), debOrder(b, j)
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		diff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if diff != 0 {
			if diff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

type debVersion struct {
	epoch    string
	hasEpoch bool
	upstream string
	revision string
}

func splitDeb(v string) (debVersion, bool) {
	var d debVersion
	if e, rest, found := strings.Cut(v, ":"); found {
		if !asciiNumber(e) {
			return d, false
		}
		d.epoch, d.hasEpoch, v = e, true, rest
	}
	d.upstream = v
	if k := strings.LastIndexByte(v, '-'); k >= 0 {
		d.upstream, d.revision = v[:k], v[k+1:]
	}
	if d.upstream == "" || !isDigit(d.upstream[0]) {
		return d, false
	}
	return d, true
}

// compareOS: distribution package versions (dpkg rule; close enough for rpm
// and apk). The epoch is compared only when both sides carry one: Trivy gives
// Debian fixes as the SOURCE package version (no epoch), while the binary
// package may carry one (bsdutils 1:2.36.1-8+deb11u1, fix 2.36.1-8+deb11u2).
func compareOS(a, b string) (int, bool) {
	da, ok1 := splitDeb(pyStrip(a))
	db, ok2 := splitDeb(pyStrip(b))
	if !ok1 || !ok2 {
		return 0, false
	}
	if da.hasEpoch && db.hasEpoch {
		if c := cmpNumber(da.epoch, db.epoch); c != 0 {
			return c, true
		}
	}
	if c := verrevcmp(da.upstream, db.upstream); c != 0 {
		return c, true
	}
	return verrevcmp(da.revision, db.revision), true
}

var (
	// Maven: RELEASE / Final / GA mean "no qualifier" (5.2.20.RELEASE == 5.2.20).
	langQualifier = regexp.MustCompile(`(?i)[.\-](release|final|ga)$`)
	langSep       = regexp.MustCompile(`[.\-_]`)
)

func langParts(v string) ([]string, bool) {
	v = pyStrip(v)
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		v = v[1:]
	}
	v = langQualifier.ReplaceAllString(v, "")
	if v == "" {
		return nil, false
	}
	parts := langSep.Split(v, -1)
	for _, p := range parts {
		if !asciiNumber(p) {
			return nil, false
		}
	}
	return parts, true
}

// compareLang: application package versions, digits only (1.2.3, 2.9.10.1).
// Versions with letters (rc1, post1) order differently per ecosystem; we do
// not guess.
func compareLang(a, b string) (int, bool) {
	pa, ok1 := langParts(a)
	pb, ok2 := langParts(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := cmpNumber(x, y); c != 0 {
			return c, true
		}
	}
	return 0, true
}

func compareVersions(a, b string, osPkg bool) (int, bool) {
	if osPkg {
		return compareOS(a, b)
	}
	return compareLang(a, b)
}

// maxVersion returns the largest version, or ok=false when the list is empty
// or two of them cannot be compared.
func maxVersion(vs []string, osPkg bool) (string, bool) {
	if len(vs) == 0 {
		return "", false
	}
	best := vs[0]
	for _, s := range vs[1:] {
		c, ok := compareVersions(s, best, osPkg)
		if !ok {
			return "", false
		}
		if c > 0 {
			best = s
		}
	}
	return best, true
}

// candidates splits the scanner's fix field (a comma-separated branch list,
// Maven "2.9.10, 2.8.11.5"; npm writes ">=4.6.0").
func candidates(fixed string) []string {
	out := []string{}
	for _, part := range strings.Split(fixed, ",") {
		x := pyStrip(part)
		if x == "" {
			continue
		}
		if strings.HasPrefix(x, ">=") {
			x = strings.TrimLeftFunc(x[2:], pyIsSpace)
		} else if strings.HasPrefix(x, "=") {
			x = strings.TrimLeftFunc(x[1:], pyIsSpace)
		}
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// pickCandidate returns the SMALLEST fix candidate above the installed
// version (stay on the same branch), or ok=false with the candidates when
// that cannot be decided.
func pickCandidate(installed, fixed string, osPkg bool) (string, bool, []string) {
	cands := candidates(fixed)
	_, langInstalled := langParts(installed)
	langInstalled = langInstalled && !osPkg
	var above []string
	for _, c := range cands {
		r, ok := compareVersions(c, installed, osPkg)
		if !ok {
			if langInstalled {
				// The installed version is plain digits; an incomparable
				// candidate is another branch's prerelease (5.0.0-beta.3).
				continue
			}
			return "", false, cands
		}
		if r > 0 {
			above = append(above, c)
		}
	}
	if len(above) == 0 {
		return "", false, cands
	}
	best := above[0]
	for _, c := range above[1:] {
		if r, ok := compareVersions(c, best, osPkg); ok && r < 0 {
			best = c
		}
	}
	return best, true, cands
}
