// Package buildinfo reads the Red Hat build information Trivy reads from an
// image layer (trivy 00b7394 pkg/fanal/analyzer/buildinfo): content manifests
// (the repositories a layer's packages came from) and the labels of the
// Dockerfile Red Hat ships in the image (the container NVR).
//
// Content manifests are plain JSON and are read exactly as Trivy does.
// Trivy parses the Dockerfile with buildkit (v0.34.2); this package
// implements the subset of that grammar Red Hat's generated Dockerfiles use
// (FROM, LABEL, ENV, RUN, CMD, ENTRYPOINT, ADD, COPY, USER, WORKDIR,
// MAINTAINER, EXPOSE, VOLUME; quotes, escapes, line continuations, comments). Anything
// outside it — an escape directive, variable substitution in a label that
// matters, heredocs, instruction flags, other instructions, anything buildkit
// would reject — is reported as Unsupported rather than guessed, so the
// caller can mark the affected packages as not checked. The subset is
// checked against buildkit itself (lab/dforacle, testdata/dockerfile_oracle).
package buildinfo

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ferhatcil/cdgate/internal/model"
)

// MaxFileBytes caps one build information file read from a layer.
const MaxFileBytes = 1 << 20

// IsContentManifest is Trivy's contentManifestAnalyzer.Required.
func IsContentManifest(p string) bool {
	dir, file := path.Split(p)
	return (dir == "root/buildinfo/content_manifests/" || dir == "usr/share/buildinfo/") && path.Ext(file) == ".json"
}

// IsDockerfile is Trivy's dockerfileAnalyzer.Required.
func IsDockerfile(p string) bool {
	dir, file := path.Split(p)
	return dir == "root/buildinfo/" && strings.HasPrefix(file, "Dockerfile")
}

// File is one build information file of a layer.
type File struct {
	Path     string
	B        []byte
	TooLarge bool // larger than MaxFileBytes: not read
}

// Merge combines one layer's build information files like Trivy's
// AnalysisResult.Merge: content sets and NVR/architecture from different
// files combine; a later file's non-empty value replaces an earlier one.
// Trivy's order between two files of the same kind in one layer is not
// defined (analyzers run concurrently); here it is path order. An unreadable
// Dockerfile or an oversized file makes the layer's build information
// unknown (known=false).
func Merge(files []File) (bi *model.BuildInfo, known bool) {
	files = append([]File(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	known = true
	for _, f := range files {
		if f.TooLarge {
			known = false
			continue
		}
		if IsContentManifest(f.Path) {
			if cs := ContentSets(f.B); cs != nil {
				if bi == nil {
					bi = &model.BuildInfo{}
				}
				bi.ContentSets = cs
			}
			continue
		}
		nvr, arch, st := Dockerfile(f.Path, f.B)
		switch st {
		case Found:
			if bi == nil {
				bi = &model.BuildInfo{}
			}
			bi.Nvr, bi.Arch = nvr, arch
		case Unsupported:
			known = false
		}
	}
	return bi, known
}

// ContentSets decodes a content manifest like Trivy (json.Decoder: the first
// JSON value only). Invalid JSON or an empty list yields nil (no build info).
func ContentSets(b []byte) []string {
	var m struct {
		ContentSets []string `json:"content_sets"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&m); err != nil || len(m.ContentSets) == 0 {
		return nil
	}
	return m.ContentSets
}

// Status is the outcome of reading a Dockerfile.
type Status int

const (
	// Found: component and architecture labels were read.
	Found Status = iota
	// NotFound: the file parses but lacks the component or architecture
	// label; Trivy records no build information for it.
	NotFound
	// Unsupported: the file uses syntax outside the implemented subset, or
	// buildkit would reject it; the result is unknown.
	Unsupported
)

var (
	reWhitespace = regexp.MustCompile(`[\t\v\f\r ]+`)
	// lineContinuationRegex for the default escape token "\".
	reContinuation = regexp.MustCompile(`([^\\])\\[ \t]*$|^\\[ \t]*$`)
	reEscapeDir    = regexp.MustCompile(`(?i)^[ \t]*#[ \t]*escape[ \t]*=`)
)

const esc = '\\'

// allowed instructions (lower case) and whether they may carry a heredoc.
var allowed = map[string]bool{
	"from": false, "label": false, "env": false, "user": false, "workdir": false, "maintainer": false,
	"run": true, "cmd": false, "entrypoint": false, "add": true, "copy": true, "expose": false, "volume": false,
}

// Dockerfile returns the NVR ("<component>-<version>-<release>", the version
// and release taken from the file name) and the architecture label, as
// Trivy's dockerfileAnalyzer does.
func Dockerfile(filePath string, b []byte) (nvr, arch string, st Status) {
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", "", Unsupported
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	lines := splitLines(b)
	for _, l := range lines {
		if reEscapeDir.Match(l) {
			return "", "", Unsupported // escape directive: a different grammar
		}
	}
	var component string
	seenFrom := false
	for i := 0; i < len(lines); i++ {
		first := trimComment(bytes.TrimLeftFunc(trimNewline(lines[i]), unicode.IsSpace))
		cur, eol := trimContinuation(first)
		if eol && len(cur) == 0 {
			continue
		}
		buf := append([]byte(nil), cur...)
		for !eol && i+1 < len(lines) {
			i++
			raw := lines[i]
			if isComment(raw) {
				continue
			}
			next := trimNewline(raw)
			if len(bytes.TrimLeftFunc(next, unicode.IsSpace)) == 0 {
				continue // empty continuation line
			}
			next, eol = trimContinuation(next)
			buf = append(buf, next...)
		}
		line := string(buf)
		parts := reWhitespace.Split(strings.TrimSpace(line), 2)
		cmd := strings.ToLower(parts[0])
		args := ""
		if len(parts) == 2 {
			args = parts[1]
		}
		heredocOK, ok := allowed[cmd]
		if !ok {
			return "", "", Unsupported
		}
		// Instruction flags ("--chown=...") are not modelled.
		if strings.HasPrefix(strings.TrimLeftFunc(args, unicode.IsSpace), "--") {
			return "", "", Unsupported
		}
		args = strings.TrimSpace(args)
		if heredocOK && strings.Contains(line, "<<") {
			return "", "", Unsupported
		}
		if cmd != "from" && !seenFrom {
			return "", "", Unsupported // buildkit: no build stage in current context
		}
		switch cmd {
		case "from":
			if args == "" || len(reWhitespace.Split(args, -1)) != 1 {
				return "", "", Unsupported
			}
			seenFrom = true
		case "user", "workdir", "maintainer", "expose":
			if args == "" {
				return "", "", Unsupported
			}
		case "run", "cmd", "entrypoint":
			if args == "" || !jsonOK(args) {
				return "", "", Unsupported
			}
		case "volume":
			if args == "" || !volumeOK(args) {
				return "", "", Unsupported
			}
		case "add", "copy":
			if strings.HasPrefix(args, "[") || len(reWhitespace.Split(args, -1)) < 2 {
				return "", "", Unsupported
			}
		case "env", "label":
			kvs, ok := parseNameVal(args)
			if !ok {
				return "", "", Unsupported
			}
			if cmd == "env" {
				continue
			}
			for _, kv := range kvs {
				if strings.ContainsRune(kv[0], '$') {
					return "", "", Unsupported
				}
				key, ok := shellWord(kv[0])
				if !ok {
					return "", "", Unsupported
				}
				switch strings.ToLower(key) {
				case "com.redhat.component", "bzcomponent", "architecture":
					if strings.ContainsRune(kv[1], '$') {
						return "", "", Unsupported
					}
					v, ok := shellWord(kv[1])
					if !ok {
						return "", "", Unsupported
					}
					if strings.ToLower(key) == "architecture" {
						arch = v
					} else {
						component = v
					}
				}
			}
		}
	}
	if !seenFrom {
		return "", "", Unsupported // buildkit: file with no instructions / no stage
	}
	if component == "" || arch == "" {
		return "", "", NotFound
	}
	return component + "-" + parseVersion(filePath), arch, Found
}

// parseVersion is Trivy's parseVersion over the Dockerfile's path.
func parseVersion(nvr string) string {
	i := strings.LastIndex(nvr, "-")
	if i < 0 {
		return ""
	}
	nv, release := nvr[:i], nvr[i+1:]
	version := ""
	if j := strings.LastIndex(nv, "-"); j >= 0 {
		version = nv[j+1:]
	}
	return version + "-" + release
}

// splitLines is buildkit's scanLines: lines keep their "\n".
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

func trimNewline(b []byte) []byte { return bytes.TrimRight(b, "\r\n") }

func isComment(b []byte) bool {
	b = bytes.TrimLeftFunc(b, unicode.IsSpace)
	return len(b) > 0 && b[0] == '#'
}

func trimComment(b []byte) []byte {
	if isComment(b) {
		return nil
	}
	return b
}

func trimContinuation(b []byte) ([]byte, bool) {
	if reContinuation.Match(b) {
		return reContinuation.ReplaceAll(b, []byte("$1")), false
	}
	return b, true
}

// jsonOK: buildkit parseMaybeJSON rejects a JSON array that is not all strings.
func jsonOK(args string) bool {
	if !strings.HasPrefix(args, "[") {
		return true
	}
	var v []any
	if err := json.Unmarshal([]byte(args), &v); err != nil {
		return true // not JSON: shell form
	}
	for _, x := range v {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return len(v) > 0
}

// volumeOK: buildkit parseMaybeJSONToList + parseVolume (a JSON array must
// hold non-blank strings; anything not JSON is split on whitespace).
func volumeOK(args string) bool {
	if !strings.HasPrefix(args, "[") {
		return true
	}
	var v []any
	if err := json.Unmarshal([]byte(args), &v); err != nil {
		return true
	}
	for _, x := range v {
		if s, ok := x.(string); !ok || strings.TrimSpace(s) == "" {
			return false
		}
	}
	return len(v) > 0
}

// parseNameVal is buildkit's parseNameVal + parseKvps for LABEL/ENV: it
// returns the raw (unprocessed) key/value pairs; ok=false where buildkit
// would fail.
func parseNameVal(rest string) ([][2]string, bool) {
	words := parseWords(rest)
	if len(words) == 0 {
		return nil, false // "requires at least one argument"
	}
	if !strings.Contains(words[0], "=") {
		parts := reWhitespace.Split(rest, 2)
		if len(parts) < 2 || parts[0] == "" {
			return nil, false
		}
		return [][2]string{{parts[0], parts[1]}}, true
	}
	var out [][2]string
	for _, w := range words {
		k, v, found := strings.Cut(w, "=")
		if !found || k == "" {
			return nil, false
		}
		out = append(out, [2]string{k, v})
	}
	return out, true
}

// parseWords is buildkit's parseWords with the default escape token.
func parseWords(rest string) []string {
	const (
		inSpaces = iota
		inWord
		inQuote
	)
	words := []string{}
	phase := inSpaces
	quote := '\000'
	blankOK := false
	var ch rune
	var w int
	var sb strings.Builder
	for pos := 0; pos <= len(rest); pos += w {
		if pos != len(rest) {
			ch, w = utf8.DecodeRuneInString(rest[pos:])
		}
		if phase == inSpaces {
			if pos == len(rest) {
				break
			}
			if unicode.IsSpace(ch) {
				continue
			}
			phase = inWord
		}
		if (phase == inWord || phase == inQuote) && pos == len(rest) {
			if blankOK || sb.Len() > 0 {
				words = append(words, sb.String())
			}
			break
		}
		if phase == inWord {
			if unicode.IsSpace(ch) {
				phase = inSpaces
				if blankOK || sb.Len() > 0 {
					words = append(words, sb.String())
				}
				sb.Reset()
				blankOK = false
				continue
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				blankOK = true
				phase = inQuote
			}
			if ch == esc {
				if pos+w == len(rest) {
					continue
				}
				sb.WriteRune(ch)
				pos += w
				ch, w = utf8.DecodeRuneInString(rest[pos:])
			}
			sb.WriteRune(ch)
			continue
		}
		if phase == inQuote {
			if ch == quote {
				phase = inWord
			}
			if ch == esc && quote != '\'' {
				if pos+w == len(rest) {
					phase = inWord
					continue
				}
				pos += w
				sb.WriteRune(ch)
				ch, w = utf8.DecodeRuneInString(rest[pos:])
			}
			sb.WriteRune(ch)
		}
	}
	return words
}

// shellWord is buildkit's shell word processing (Lex.ProcessWordWithMatches,
// RawEscapes off) for a word without "$": quotes are removed, the escape
// token escapes the next character outside quotes and `"`, `$` or itself
// inside double quotes. ok=false for an unterminated quote.
func shellWord(s string) (string, bool) {
	r := []rune(s)
	var b strings.Builder
	i := 0
loop:
	for i < len(r) {
		c := r[i]
		switch c {
		case '\'':
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			if j == len(r) {
				return "", false
			}
			b.WriteString(string(r[i+1 : j]))
			i = j + 1
		case '"':
			i++
			for {
				if i == len(r) {
					return "", false
				}
				c := r[i]
				i++
				if c == '"' {
					break
				}
				if c == esc {
					if i == len(r) {
						continue
					}
					switch r[i] {
					case '"', '$', esc:
						c = r[i]
						i++
					}
				}
				b.WriteRune(c)
			}
		default:
			i++
			if c == esc {
				if i == len(r) {
					break loop
				}
				c = r[i]
				i++
			}
			b.WriteRune(c)
		}
	}
	return b.String(), true
}
