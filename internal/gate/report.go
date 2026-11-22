// Package gate implements `cdgate gate`: read a Trivy or Grype JSON report,
// ask CyberDetails about the CVE identifiers only, join the answer with the
// packages locally, and build a fix plan.
//
// It is a port of the Python gate (cyberdetails.sca/cd_sca_gate.py). The
// golden files in testdata/ are produced by the Python gate on the same
// reports and the same server answers (cyberdetails.sca/lab/gate_golden.py),
// and gate_test.go checks that both produce the same findings, fix plan and
// text. Deliberate differences:
//   - a report whose fields have an unexpected JSON type (an object where a
//     string is expected, a number where a list is expected) is refused with
//     exit 2; the Python gate skips some of these shapes;
//   - a number in a scalar field is kept as written in the JSON ("1e3"),
//     Python prints its float value ("1000.0").
//
// Neither shape is produced by Trivy or Grype.
package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxReportBytes caps the report read into memory.
const MaxReportBytes = 200 << 20

var cvePattern = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,7}$`)

// OS package types (Grype artifact.type); Trivy says Class == "os-pkgs".
var osTypes = map[string]bool{"deb": true, "apk": true, "rpm": true, "alpm": true, "portage": true}

// Finding is one scanner finding plus, after Join, the CyberDetails verdict.
// Field order is the JSON key order of the Python gate.
type Finding struct {
	PkgType         string          `json:"pkg_type"`
	OSPackage       bool            `json:"os_package"`
	ID              string          `json:"id"`
	CVE             *string         `json:"cve"`
	Package         string          `json:"package"`
	Installed       string          `json:"installed"`
	Fixed           string          `json:"fixed"`
	Target          string          `json:"target"`
	ScannerSeverity string          `json:"scanner_severity"`
	Urgency         string          `json:"urgency"`
	Blocked         bool            `json:"blocked"`
	Reasons         []string        `json:"reasons"`
	URL             *string         `json:"url"`
	Signals         json.RawMessage `json:"signals"`
	Mitigation      *Mitigation     `json:"mitigation"`
}

// key is "cve or id", the identifier a finding is grouped under.
func (f Finding) key() string {
	if f.CVE != nil {
		return *f.CVE
	}
	return f.ID
}

// Mitigation is the validated, sanitised form printed and written to JSON.
type Mitigation struct {
	Detection              *Detection `json:"detection"`
	Workarounds            []string   `json:"workarounds"`
	WorkaroundsAIGenerated bool       `json:"workarounds_ai_generated"`
}

// Detection links to the record's SIEM queries on the site.
type Detection struct {
	URL     string   `json:"url"`
	Formats []string `json:"formats"`
	PackURL *string  `json:"pack_url"`
}

// Meta describes the scanned operating system (only Trivy reports EOSL).
type Meta struct {
	OS   *string `json:"os"`
	EOSL *bool   `json:"eosl"`
}

var errMalformed = errors.New("report has an unexpected structure (not Trivy or Grype JSON output)")

// pyIsSpace is Python's str.isspace(): Go's unicode.IsSpace plus the
// information separators U+001C..U+001F.
func pyIsSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// scalar is Python's str(v or "") for a JSON scalar. A list or object in a
// scalar field is malformed.
func scalar(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case bool:
		if t {
			return "True", nil
		}
		return "", nil
	case json.Number:
		if f, err := strconv.ParseFloat(string(t), 64); err == nil && f == 0 {
			return "", nil
		}
		return string(t), nil
	}
	return "", errMalformed
}

// reportText mirrors _rapor_metni: control (Cc), format (Cf) and line or
// paragraph separator (Zl, Zp) characters are dropped, tab and newline become
// a space, then the text is cut to n characters. The scanner reads a pull
// request's lockfile; a version or path may carry ANSI escapes or bidi marks.
func reportText(v any, n int) (string, error) {
	s, err := scalar(v)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count == n {
			break
		}
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			r = ' '
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp):
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String(), nil
}

func asCVE(v any) *string {
	s, err := scalar(v)
	if err != nil {
		return nil
	}
	s = strings.ToUpper(pyStrip(s))
	if !cvePattern.MatchString(s) {
		return nil
	}
	return &s
}

// object is Python's `v or {}` followed by .get(): a falsy value is empty, a
// non-object is malformed.
func object(v any) (map[string]any, error) {
	switch t := v.(type) {
	case map[string]any:
		return t, nil
	case nil:
		return nil, nil
	case bool:
		if !t {
			return nil, nil
		}
	case string:
		if t == "" {
			return nil, nil
		}
	case []any:
		if len(t) == 0 {
			return nil, nil
		}
	}
	return nil, errMalformed
}

// list is Python's `v or []` used in a for loop.
func list(v any) ([]any, error) {
	switch t := v.(type) {
	case []any:
		return t, nil
	case nil:
		return nil, nil
	case bool:
		if !t {
			return nil, nil
		}
	case string:
		if t == "" {
			return nil, nil
		}
	case map[string]any:
		if len(t) == 0 {
			return nil, nil
		}
	}
	return nil, errMalformed
}

func newFinding(id, pkg, installed, fixed, target, severity, typ any, cve *string, osPkg bool) (Finding, error) {
	f := Finding{CVE: cve, OSPackage: osPkg}
	for _, x := range []struct {
		dst *string
		v   any
		n   int
	}{{&f.PkgType, typ, 40}, {&f.ID, id, 80}, {&f.Package, pkg, 200}, {&f.Installed, installed, 80},
		{&f.Fixed, fixed, 200}, {&f.Target, target, 300}, {&f.ScannerSeverity, severity, 20}} {
		s, err := reportText(x.v, x.n)
		if err != nil {
			return Finding{}, err
		}
		*x.dst = s
	}
	return f, nil
}

// Read parses a Trivy or Grype JSON report ("-" = stdin).
func Read(path string) (string, []Finding, Meta, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", nil, Meta{}, fmt.Errorf("cannot read report: %w", err)
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return "", nil, Meta{}, fmt.Errorf("cannot read report: %w", err)
	}
	if len(data) > MaxReportBytes {
		return "", nil, Meta{}, errors.New("report is larger than 200 MB")
	}
	return Parse(data)
}

// Parse decodes a report already in memory.
func Parse(data []byte) (string, []Finding, Meta, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return "", nil, Meta{}, errors.New("report is not valid JSON: not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", nil, Meta{}, fmt.Errorf("report is not valid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", nil, Meta{}, errors.New("report is not valid JSON: extra data after the document")
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return "", nil, Meta{}, errors.New("report must be a JSON object (Trivy or Grype JSON output)")
	}
	var (
		tool     string
		findings []Finding
		err      error
	)
	_, hasMatches := doc["matches"]
	_, hasResults := doc["Results"]
	_, hasSchema := doc["SchemaVersion"]
	switch {
	case hasMatches:
		tool = "grype"
		findings, err = grype(doc)
	case hasResults || hasSchema:
		tool = "trivy"
		findings, err = trivy(doc)
	default:
		return "", nil, Meta{}, errors.New("unrecognised report: expected Trivy JSON (`--format json`) or Grype JSON (`-o json`)")
	}
	if err != nil {
		return "", nil, Meta{}, err
	}
	meta, err := readMeta(doc)
	if err != nil {
		return "", nil, Meta{}, err
	}
	return tool, findings, meta, nil
}

func trivy(doc map[string]any) ([]Finding, error) {
	results, err := list(doc["Results"])
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, res := range results {
		r, ok := res.(map[string]any)
		if !ok {
			continue // Python: `if not isinstance(sonuc, dict): continue`
		}
		vulns, err := list(r["Vulnerabilities"])
		if err != nil {
			return nil, err
		}
		for _, vv := range vulns {
			v, ok := vv.(map[string]any)
			if !ok {
				continue
			}
			cve := asCVE(v["VulnerabilityID"])
			if cve == nil {
				// Trivy sometimes carries the CVE only in VendorIDs (GHSA id).
				ids, err := list(v["VendorIDs"])
				if err != nil {
					return nil, err
				}
				for _, e := range ids {
					if cve = asCVE(e); cve != nil {
						break
					}
				}
			}
			f, err := newFinding(v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"], v["FixedVersion"],
				r["Target"], v["Severity"], r["Type"], cve, r["Class"] == "os-pkgs")
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// pyRepr is Python's str(x) for one element of Grype's fix.versions.
func pyRepr(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "None", nil
	case bool:
		if t {
			return "True", nil
		}
		return "False", nil
	case string:
		return t, nil
	case json.Number:
		return string(t), nil
	}
	return "", errMalformed
}

func grype(doc map[string]any) ([]Finding, error) {
	matches, err := list(doc["matches"])
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, mm := range matches {
		x, ok := mm.(map[string]any)
		if !ok {
			continue
		}
		vuln, err := object(x["vulnerability"])
		if err != nil {
			return nil, err
		}
		art, err := object(x["artifact"])
		if err != nil {
			return nil, err
		}
		cve := asCVE(vuln["id"])
		if cve == nil {
			related, err := list(x["relatedVulnerabilities"])
			if err != nil {
				return nil, err
			}
			for _, rv := range related {
				r, err := object(rv)
				if err != nil {
					return nil, err
				}
				if cve = asCVE(r["id"]); cve != nil {
					break
				}
			}
		}
		fix, err := object(vuln["fix"])
		if err != nil {
			return nil, err
		}
		versions, err := list(fix["versions"])
		if err != nil {
			return nil, err
		}
		var fixes []string
		for i, fv := range versions {
			if i == 5 {
				break
			}
			s, err := pyRepr(fv)
			if err != nil {
				return nil, err
			}
			fixes = append(fixes, s)
		}
		locs, err := list(art["locations"])
		if err != nil {
			return nil, err
		}
		var location any
		for _, lc := range locs {
			lo, err := object(lc)
			if err != nil {
				return nil, err
			}
			if s, err := scalar(lo["path"]); err != nil {
				return nil, err
			} else if s != "" {
				location = lo["path"]
				break
			}
		}
		typ, err := scalar(art["type"])
		if err != nil {
			return nil, err
		}
		f, err := newFinding(vuln["id"], art["name"], art["version"], strings.Join(fixes, ", "),
			location, vuln["severity"], art["type"], cve, osTypes[typ])
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func readMeta(doc map[string]any) (Meta, error) {
	if md, ok := doc["Metadata"].(map[string]any); ok {
		if osInfo, ok := md["OS"].(map[string]any); ok {
			fam, err := scalar(osInfo["Family"])
			if err != nil {
				return Meta{}, err
			}
			if fam != "" {
				name, err := scalar(osInfo["Name"])
				if err != nil {
					return Meta{}, err
				}
				s, _ := reportText(pyStrip(fam+" "+name), 60)
				e := osInfo["EOSL"] == true
				return Meta{OS: &s, EOSL: &e}, nil
			}
		}
	}
	if d, ok := doc["distro"].(map[string]any); ok {
		name, err := scalar(d["name"])
		if err != nil {
			return Meta{}, err
		}
		if name != "" {
			ver, err := scalar(d["version"])
			if err != nil {
				return Meta{}, err
			}
			s, _ := reportText(pyStrip(name+" "+ver), 60)
			return Meta{OS: &s}, nil
		}
	}
	return Meta{}, nil
}

// cut is Python's s[:n] (characters, not bytes).
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
