package langpkg

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/plan9obj"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

// GoBinary is what is kept of a Go executable: its build information and the
// main module version chosen the way Trivy chooses it.
type GoBinary struct {
	Info        *debug.BuildInfo
	MainVersion string // "" when no version could be determined
}

// GoExeCandidate mirrors the format switch in debug/buildinfo's
// readRawBuildInfo (Go 1.27): fewer than 16 bytes or another prefix is
// "unrecognized file format" there, so such a file need not be read further.
func GoExeCandidate(ident []byte) bool {
	if len(ident) < 16 {
		return false
	}
	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")),
		bytes.HasPrefix(ident, []byte("MZ")),
		bytes.HasPrefix(ident, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(ident[1:], []byte("\xFA\xED\xFE")),
		bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBE")) || bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBF")),
		bytes.HasPrefix(ident, []byte{0x01, 0xDF}) || bytes.HasPrefix(ident, []byte{0x01, 0xF7}):
		return true
	}
	switch binary.BigEndian.Uint32(ident) {
	case plan9obj.Magic386, plan9obj.MagicAMD64, plan9obj.MagicARM:
		return true
	}
	return false
}

// ReadGoBinary returns nil for anything that is not a Go executable. The
// stdlib parsers are hardened, but the input is untrusted, so a panic means
// "not readable".
func ReadGoBinary(b []byte) (g *GoBinary) {
	defer func() {
		if recover() != nil {
			g = nil
		}
	}()
	info, err := buildinfo.Read(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	g = &GoBinary{Info: info}
	if info.Main.Path != "" {
		v := info.Main.Version
		if v == "(devel)" {
			v = ""
		}
		g.MainVersion = chooseMainVersion(v, ldflagsVersion(info.Main.Path, info.Settings),
			elfSymbolVersion(b, info.Main.Path))
	}
	return g
}

// chooseMainVersion is Trivy's (dependency/parser/golang/binary/parse.go).
func chooseMainVersion(version, ldflags, elfVersion string) string {
	switch {
	case version != "" && !isPseudoVersion(version):
		return version
	case ldflags != "":
		return ldflags
	case elfVersion != "":
		return elfVersion
	}
	return version
}

// --- golang.org/x/mod v0.42.0 semver.IsValid and module.IsPseudoVersion ---

func semverValid(v string) bool {
	if v == "" || v[0] != 'v' {
		return false
	}
	_, v, ok := semverInt(v[1:])
	if !ok {
		return false
	}
	if v == "" {
		return true
	}
	if v[0] != '.' {
		return false
	}
	if _, v, ok = semverInt(v[1:]); !ok {
		return false
	}
	if v == "" {
		return true
	}
	if v[0] != '.' {
		return false
	}
	if _, v, ok = semverInt(v[1:]); !ok {
		return false
	}
	if len(v) > 0 && v[0] == '-' {
		if v, ok = semverIdents(v, true); !ok {
			return false
		}
	}
	if len(v) > 0 && v[0] == '+' {
		if v, ok = semverIdents(v, false); !ok {
			return false
		}
	}
	return v == ""
}

func semverInt(v string) (t, rest string, ok bool) {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return "", "", false
	}
	i := 1
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if v[0] == '0' && i != 1 {
		return "", "", false
	}
	return v[:i], v[i:], true
}

// semverIdents parses "-pre.release" (stops at '+'; numeric identifiers
// without leading zeros) or "+build.meta" (runs to the end).
func semverIdents(v string, pre bool) (rest string, ok bool) {
	i, start := 1, 1
	for i < len(v) && !(pre && v[i] == '+') {
		c := v[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", false
		}
		if c == '.' {
			if start == i || (pre && badNum(v[start:i])) {
				return "", false
			}
			start = i + 1
		}
		i++
	}
	if start == i || (pre && badNum(v[start:i])) {
		return "", false
	}
	return v[i:], true
}

func badNum(v string) bool {
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	return i == len(v) && i > 1 && v[0] == '0'
}

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func isPseudoVersion(v string) bool {
	return strings.Count(v, "-") >= 2 && semverValid(v) && pseudoVersionRE.MatchString(v)
}

// --- version from -ldflags -X (Trivy ParseLDFlags) ---

func isVersionXKey(key string) bool {
	key = strings.ToLower(key)
	return strings.HasSuffix(key, ".version") || strings.HasSuffix(key, ".ver")
}

func isValidSemVer(v string) bool { return semverValid(v) || semverValid("v"+v) }

var defaultVersionPrefixes = map[string]bool{"main": true, "common": true, "version": true, "cmd": true}

func versionPrefix(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	s, _, _ = strings.Cut(s, ".")
	return strings.ToLower(s)
}

// classify: [0] <module>/cmd/..., [1] main/common/version/cmd prefix, [2] other.
func classify(found *[3][]string, key, module, val string) {
	switch {
	case strings.HasPrefix(key, module+"/cmd/"):
		found[0] = append(found[0], val)
	case defaultVersionPrefixes[versionPrefix(key)]:
		found[1] = append(found[1], val)
	default:
		found[2] = append(found[2], val)
	}
}

// chooseVersion: the first tier that has values; more than one value there
// means no version (Trivy does not fall through to the next tier).
func chooseVersion(found [3][]string) string {
	for _, vs := range found {
		if len(vs) == 0 {
			continue
		}
		if len(vs) > 1 {
			return ""
		}
		return vs[0]
	}
	return ""
}

func ldflagsVersion(module string, settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key != "-ldflags" {
			continue
		}
		args, err := shellSplit(s.Value)
		if err != nil {
			return ""
		}
		x, err := xFlags(args)
		if err != nil {
			return ""
		}
		var found [3][]string
		for k, v := range x {
			k = strings.TrimLeft(k, "'")
			v = strings.TrimRight(v, "'")
			if isVersionXKey(k) && isValidSemVer(v) {
				classify(&found, k, module, v)
			}
		}
		return chooseVersion(found)
	}
	return ""
}

var errUnsupportedShell = errors.New("ldflags use shell syntax not reproduced here")

// shellSplit is go-shellwords v1.0.16 Parse with its defaults (no env,
// backtick or comment handling) for strings made of words, quotes and
// backslash escapes. Shell operators and substitutions (` ( ) ; & | < >)
// change how go-shellwords cuts the string; rather than approximate them we
// refuse, and the caller reports no version (never a different one).
func shellSplit(line string) ([]string, error) {
	if strings.ContainsAny(line, "`();&|<>") {
		return nil, errUnsupportedShell
	}
	const (
		argNo = iota
		argSingle
		argQuoted
	)
	var args []string
	var buf []byte
	got := argNo
	escaped, dq, sq := false, false, false
	flush := func() {
		if got == argQuoted || (got != argNo && len(buf) > 0) {
			args = append(args, string(buf))
		}
		buf, got = buf[:0], argNo
	}
	for _, r := range line {
		if escaped {
			escaped = false
			switch r {
			case 't':
				r = '\t'
			case 'n':
				r = '\n'
			}
			buf = append(buf, string(r)...)
			got = argSingle
			continue
		}
		if r == '\\' {
			if sq {
				buf = append(buf, '\\')
			} else {
				escaped = true
			}
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			if sq || dq {
				buf = append(buf, byte(r))
			} else {
				flush()
			}
			continue
		}
		if r == '"' && !sq {
			if dq {
				got = argQuoted
			}
			dq = !dq
			continue
		}
		if r == '\'' && !dq {
			if sq {
				got = argQuoted
			}
			sq = !sq
			continue
		}
		got = argSingle
		buf = append(buf, string(r)...)
	}
	flush()
	if escaped || sq || dq {
		return nil, errors.New("invalid command line string")
	}
	return args, nil
}

// xFlags is the pflag v1.0.10 parse Trivy runs: a FlagSet with only -X
// (StringToString, no long name) and -h/--help (bool), unknown flags allowed.
func xFlags(args []string) (map[string]string, error) {
	x := map[string]string{}
	set := func(val string) error { // stringToStringValue.Set
		var pairs []string
		switch strings.Count(val, "=") {
		case 0:
			return errors.New("must be formatted as key=value")
		case 1:
			pairs = []string{strings.Trim(val, `"`)}
		default:
			rec, err := csv.NewReader(strings.NewReader(val)).Read()
			if err != nil {
				return err
			}
			pairs = rec
		}
		out := map[string]string{}
		for _, p := range pairs {
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				return errors.New("must be formatted as key=value")
			}
			out[k] = v
		}
		for k, v := range out {
			x[k] = v
		}
		return nil
	}
	strip := func(a []string) []string { // stripUnknownFlagValue
		if len(a) == 0 || (len(a[0]) > 0 && a[0][0] == '-') {
			return a
		}
		if len(a) > 1 {
			return a[1:]
		}
		return nil
	}
	for len(args) > 0 {
		s := args[0]
		args = args[1:]
		if len(s) == 0 || s[0] != '-' || len(s) == 1 {
			continue // positional
		}
		if s[1] == '-' {
			if len(s) == 2 {
				break // "--" ends flags
			}
			name := s[2:]
			if name[0] == '-' || name[0] == '=' {
				return nil, errors.New("bad flag syntax")
			}
			n, val, hasVal := strings.Cut(name, "=")
			switch {
			case n == "help":
				if hasVal {
					if _, err := strconv.ParseBool(val); err != nil {
						return nil, err
					}
				}
			case hasVal:
			default:
				args = strip(args)
			}
			continue
		}
		// short flags: each iteration of pflag's parseShortArg starts from
		// the same args; the result is the last iteration's.
		orig, out := args, args
		sh := s[1:]
		for len(sh) > 0 {
			if strings.HasPrefix(sh, "test.") {
				out = orig // isGotestShorthandFlag: args unchanged
				break
			}
			c, rest := sh[0], sh[1:]
			out = orig
			switch c {
			case 'X':
				var val string
				switch {
				case len(sh) > 2 && sh[1] == '=':
					val, rest = sh[2:], ""
				case len(sh) > 1:
					val, rest = sh[1:], ""
				case len(orig) > 0:
					val, out = orig[0], orig[1:]
				default:
					return nil, errors.New("flag needs an argument: -X")
				}
				if err := set(val); err != nil {
					return nil, err
				}
			case 'h':
				if len(sh) > 2 && sh[1] == '=' {
					if _, err := strconv.ParseBool(sh[2:]); err != nil {
						return nil, err
					}
					rest = ""
				}
			default:
				if len(sh) > 2 && sh[1] == '=' {
					rest = ""
				} else {
					out = strip(orig)
				}
			}
			sh = rest
		}
		args = out
	}
	return x, nil
}

// elfSymbolVersion is Trivy's elf.go: string symbols "<key>.str" whose key is
// a version key and whose value is a valid semver, tiered like -ldflags.
func elfSymbolVersion(b []byte, module string) string {
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	syms, err := f.Symbols()
	if err != nil {
		return ""
	}
	var found [3][]string
	for i := range syms {
		s := &syms[i]
		if !strings.HasSuffix(s.Name, ".str") || s.Size == 0 {
			continue
		}
		key := strings.TrimSuffix(s.Name, ".str")
		// Size cap: Trivy allocates sym.Size bytes from an untrusted header; a
		// version string is never near 4 KiB.
		if !isVersionXKey(key) || int(s.Section) >= len(f.Sections) || s.Size > 4096 {
			continue
		}
		sec := f.Sections[s.Section]
		buf := make([]byte, s.Size)
		if _, err := sec.ReadAt(buf, int64(s.Value-sec.Addr)); err != nil {
			continue
		}
		v := strings.TrimRight(string(buf), "\x00")
		if v == "" || !isValidSemVer(v) {
			continue
		}
		classify(&found, key, module, v)
	}
	return chooseVersion(found)
}
